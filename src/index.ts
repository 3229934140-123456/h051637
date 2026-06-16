export * from './types';
export * from './acme-client';
export * from './challenge-responder';
export * from './certificate-store';
export * from './renewal-scheduler';
export * from './tls-termination';

import {
  AcmeClientConfig,
  CertificateRequest,
  CertificateStorageConfig,
  ChallengeType,
  LETSENCRYPT_STAGING_DIRECTORY,
  LETSENCRYPT_PRODUCTION_DIRECTORY,
  DnsProvider,
  RenewalConfig,
  RenewalPolicy,
  TLSTerminationConfig,
  StoredCertificate,
  ManagedServiceStatus,
  CertificateRenewalStatus,
  RenewalTask,
} from './types';

import { AcmeClient } from './acme-client';
import { ChallengeResponder } from './challenge-responder';
import { CertificateStore } from './certificate-store';
import { RenewalScheduler } from './renewal-scheduler';
import { TLSTermination, RequestHandler } from './tls-termination';

function inferChallengeType(domains: string[]): ChallengeType {
  for (const d of domains) {
    if (d.startsWith('*.')) {
      return 'dns-01';
    }
  }
  return 'http-01';
}

function hasWildcardDomain(domains: string[]): boolean {
  return domains.some((d) => d.startsWith('*.'));
}

function resolveChallengeType(
  domains: string[],
  preferredType?: ChallengeType
): ChallengeType {
  const hasWildcard = hasWildcardDomain(domains);
  if (hasWildcard) {
    return 'dns-01';
  }
  return preferredType || 'http-01';
}

export interface AcmeTlsManagerConfig {
  acme?: Partial<AcmeClientConfig>;
  storage?: Partial<CertificateStorageConfig>;
  renewal?: Partial<RenewalConfig>;
  tls?: Partial<TLSTerminationConfig>;
  challenge?: {
    dnsProvider?: DnsProvider;
  };
  domains?: Array<{
    domains: string[];
    challengeType: ChallengeType;
  }>;
  useProduction?: boolean;
  contactEmail?: string;
  storageDir?: string;
}

export class AcmeTlsManager {
  private config: AcmeTlsManagerConfig;
  private acmeClient: AcmeClient | null = null;
  private challengeResponder: ChallengeResponder | null = null;
  private certStore: CertificateStore | null = null;
  private renewalScheduler: RenewalScheduler | null = null;
  private tlsTermination: TLSTermination | null = null;
  private isInitialized: boolean = false;
  private isStarted: boolean = false;

  constructor(config: AcmeTlsManagerConfig = {}) {
    this.config = config;
  }

  async initialize(): Promise<void> {
    if (this.isInitialized) {
      return;
    }

    const baseDir =
      this.config.storageDir || process.env.ACME_STORAGE_DIR || './acme-data';

    this.certStore = new CertificateStore({
      storageDir: baseDir,
      encryptPrivateKeys: this.config.storage?.encryptPrivateKeys ?? false,
      encryptionPassphrase: this.config.storage?.encryptionPassphrase,
      filePermissions: this.config.storage?.filePermissions ?? 0o600,
    });
    await this.certStore.initialize();

    this.challengeResponder = new ChallengeResponder(
      this.config.challenge?.dnsProvider
    );

    const directoryUrl = this.config.useProduction
      ? LETSENCRYPT_PRODUCTION_DIRECTORY
      : LETSENCRYPT_STAGING_DIRECTORY;

    this.acmeClient = new AcmeClient({
      directoryUrl,
      contact: this.config.contactEmail
        ? [`mailto:${this.config.contactEmail}`]
        : undefined,
      agreeToTerms: true,
      ...this.config.acme,
    });

    await this.acmeClient.initialize();

    this.tlsTermination = new TLSTermination(
      this.certStore,
      this.challengeResponder,
      {
        httpPort: 80,
        httpsPort: 443,
        ...this.config.tls,
      }
    );

    this.isInitialized = true;

    const stats = this.certStore.getStorageStats();
    console.log(
      `[AcmeTlsManager] Initialized with ${stats.totalCertificates} certificates managing ${stats.managedDomains} domains`
    );
  }

  async start(requestHandler?: RequestHandler): Promise<void> {
    if (!this.isInitialized) {
      await this.initialize();
    }

    if (this.isStarted) {
      return;
    }

    if (requestHandler) {
      this.tlsTermination!.setRequestHandler(requestHandler);
    }

    if (this.config.domains && this.config.domains.length > 0) {
      await this.ensureCertificates();
    }

    await this.tlsTermination!.start();

    this.setupRenewalScheduler();

    this.isStarted = true;

    console.log('[AcmeTlsManager] Started successfully');
  }

  private async ensureCertificates(): Promise<void> {
    if (!this.config.domains) return;

    for (const domainConfig of this.config.domains) {
      const primaryDomain = domainConfig.domains[0];
      const existing = await this.certStore!.getCertificateByDomain(
        primaryDomain
      );

      if (existing) {
        const now = new Date();
        const renewBefore = this.config.renewal?.renewBeforeDays ?? 30;
        const expiryThreshold = new Date(
          now.getTime() + renewBefore * 24 * 60 * 60 * 1000
        );

        if (existing.expiresAt > expiryThreshold) {
          console.log(
            `[AcmeTlsManager] Certificate for ${primaryDomain} already valid until ${existing.expiresAt.toISOString()}`
          );
          continue;
        }

        console.log(
          `[AcmeTlsManager] Certificate for ${primaryDomain} will expire soon, renewing...`
        );
      }

      try {
        await this.requestCertificate({
          domains: domainConfig.domains,
          challengeType: resolveChallengeType(
            domainConfig.domains,
            domainConfig.challengeType
          ),
          dnsProvider: this.config.challenge?.dnsProvider,
        });
      } catch (err) {
        console.error(
          `[AcmeTlsManager] Failed to get certificate for ${primaryDomain}: ${(err as Error).message}`
        );
      }
    }
  }

  private setupRenewalScheduler(): void {
    if (!this.config.domains || this.config.domains.length === 0) {
      return;
    }

    const policy: RenewalPolicy = {
      dnsProvider: this.config.challenge?.dnsProvider,
      onRenewalSuccess: async (oldCert: StoredCertificate, newCert: StoredCertificate) => {
        console.log(
          `[AcmeTlsManager] Renewal succeeded: ${oldCert.domain} (${oldCert.serialNumber} -> ${newCert.serialNumber})`
        );
        this.tlsTermination!.invalidateContextCache(oldCert.domain);
      },
      onRenewalError: async (cert: StoredCertificate, error: Error, attempt: number) => {
        console.error(
          `[AcmeTlsManager] Renewal attempt ${attempt} failed for ${cert.domain}: ${error.message}`
        );
      },
    };

    this.renewalScheduler = new RenewalScheduler(
      this.acmeClient!,
      this.certStore!,
      this.challengeResponder!,
      this.config.renewal || {},
      policy
    );

    this.renewalScheduler.start();
  }

  async requestCertificate(
    request: CertificateRequest
  ): Promise<StoredCertificate> {
    if (!this.isInitialized) {
      await this.initialize();
    }

    const effectiveChallengeType = resolveChallengeType(
      request.domains,
      request.challengeType
    );

    if (
      hasWildcardDomain(request.domains) &&
      request.challengeType !== 'dns-01'
    ) {
      console.warn(
        `[AcmeTlsManager] Domain group ${request.domains[0]} has wildcard(s), forcing DNS-01 challenge (original: ${request.challengeType})`
      );
    }

    const existingCert = await this.certStore!.getCertificateByDomain(
      request.domains[0]
    );

    const activeTokens: Array<{
      type: ChallengeType;
      token: string;
      keyAuth: string;
      domain: string;
    }> = [];

    try {
      const result = await this.acmeClient!.issueCertificate(
        {
          ...request,
          challengeType: effectiveChallengeType,
        },
        async (
          challenge,
          keyAuthorization,
          domain
        ) => {
          await this.challengeResponder!.registerChallenge(
            effectiveChallengeType,
            challenge.token,
            keyAuthorization,
            domain
          );
          activeTokens.push({
            type: effectiveChallengeType,
            token: challenge.token,
            keyAuth: keyAuthorization,
            domain,
          });

          if (effectiveChallengeType === 'http-01') {
            await this.sleep(1000);
          } else if (effectiveChallengeType === 'dns-01') {
            await this.sleep(10000);
          }
        }
      );

      for (const token of activeTokens) {
        try {
          await this.challengeResponder!.unregisterChallenge(
            token.type,
            token.token,
            token.keyAuth,
            token.domain
          );
        } catch (cleanupErr) {
          console.warn(
            `[AcmeTlsManager] Failed to cleanup challenge after success: ${(cleanupErr as Error).message}`
          );
        }
      }

      const certInfo = this.certStore!.parseCertificateInfo(result.certificate);

      const storedCert: StoredCertificate = {
        domain: request.domains[0],
        domains: request.domains,
        certificate: result.certificate,
        chain: result.chain,
        fullchain: result.fullchain,
        privateKey: result.privateKey,
        serialNumber: certInfo.serialNumber,
        issuedAt: certInfo.issuedAt,
        expiresAt: certInfo.expiresAt,
        issuer: certInfo.issuer,
        challengeType: effectiveChallengeType,
      };

      await this.certStore!.saveCertificate(storedCert);

      if (this.tlsTermination) {
        for (const domain of request.domains) {
          this.tlsTermination.invalidateContextCache(domain);
        }
        const currentDefault = this.tlsTermination.getDefaultDomain();
        if (currentDefault && request.domains.includes(currentDefault)) {
          this.tlsTermination.setDefaultDomain(request.domains[0]);
        }
      }

      if (existingCert && existingCert.serialNumber !== storedCert.serialNumber) {
        await this.certStore!.removeCertificate(existingCert.serialNumber);
        console.log(
          `[AcmeTlsManager] Removed old certificate for ${storedCert.domain} (serial: ${existingCert.serialNumber})`
        );
      }

      console.log(
        `[AcmeTlsManager] Certificate issued for ${request.domains.join(', ')} with ${effectiveChallengeType} (expires ${storedCert.expiresAt.toISOString()})`
      );

      return storedCert;
    } catch (err) {
      for (const token of activeTokens) {
        try {
          await this.challengeResponder!.unregisterChallenge(
            token.type,
            token.token,
            token.keyAuth,
            token.domain
          );
        } catch (cleanupErr) {
          console.warn(
            `[AcmeTlsManager] Failed to cleanup challenge after error: ${(cleanupErr as Error).message}`
          );
        }
      }
      throw err;
    }
  }

  async forceRenewal(domain: string): Promise<void> {
    if (!this.renewalScheduler) {
      throw new Error('Renewal scheduler not started');
    }
    await this.renewalScheduler.forceRenewal(domain);
  }

  async stop(): Promise<void> {
    if (!this.isStarted) {
      return;
    }

    if (this.renewalScheduler) {
      this.renewalScheduler.stop();
    }

    if (this.tlsTermination) {
      await this.tlsTermination.stop();
    }

    this.isStarted = false;
    console.log('[AcmeTlsManager] Stopped');
  }

  getAcmeClient(): AcmeClient | null {
    return this.acmeClient;
  }

  getCertificateStore(): CertificateStore | null {
    return this.certStore;
  }

  getChallengeResponder(): ChallengeResponder | null {
    return this.challengeResponder;
  }

  getRenewalScheduler(): RenewalScheduler | null {
    return this.renewalScheduler;
  }

  getTlsTermination(): TLSTermination | null {
    return this.tlsTermination;
  }

  async getStatus(): Promise<{
    initialized: boolean;
    started: boolean;
    storage: ReturnType<CertificateStore['getStorageStats']>;
    certificates: Array<{
      domain: string;
      serialNumber: string;
      expiresAt: Date;
      daysUntilExpiry: number;
      challengeType: ChallengeType;
    }>;
    renewal?: ReturnType<RenewalScheduler['getStatus']>;
    tls?: ReturnType<TLSTermination['getStats']>;
  }> {
    const certs = await this.certStore!.getAllCertificates();
    const now = new Date();

    return {
      initialized: this.isInitialized,
      started: this.isStarted,
      storage: this.certStore!.getStorageStats(),
      certificates: certs.map((c) => ({
        domain: c.domain,
        serialNumber: c.serialNumber,
        expiresAt: c.expiresAt,
        daysUntilExpiry: Math.ceil(
          (c.expiresAt.getTime() - now.getTime()) / (24 * 60 * 60 * 1000)
        ),
        challengeType: c.challengeType,
      })),
      renewal: this.renewalScheduler?.getStatus(),
      tls: this.tlsTermination?.getStats(),
    };
  }

  async getManagedStatus(): Promise<ManagedServiceStatus> {
    if (!this.isInitialized) {
      await this.initialize();
    }

    const certs = await this.certStore!.getAllCertificates();
    const now = new Date();
    const renewalThreshold = new Date(
      now.getTime() +
        (this.config.renewal?.renewBeforeDays ?? 30) * 24 * 60 * 60 * 1000
    );

    const serialToCert = new Map<string, StoredCertificate>();
    for (const cert of certs) {
      serialToCert.set(cert.serialNumber, cert);
    }

    const managedDomainCerts = this.certStore!.getManagedDomains();
    const domainToSerial = new Map<string, string>();
    for (const domain of managedDomainCerts) {
      const cert = await this.certStore!.getCertificateByDomain(domain);
      if (cert) {
        domainToSerial.set(domain, cert.serialNumber);
      }
    }

    const certsWithStatus: CertificateRenewalStatus[] = [];
    const processedSerials = new Set<string>();

    for (const cert of certs) {
      if (processedSerials.has(cert.serialNumber)) continue;
      processedSerials.add(cert.serialNumber);

      const daysUntilExpiry = Math.ceil(
        (cert.expiresAt.getTime() - now.getTime()) / (24 * 60 * 60 * 1000)
      );

      let renewalTask: RenewalTask | undefined;
      if (this.renewalScheduler) {
        renewalTask = this.renewalScheduler.getTaskForDomain(cert.domain);
      }

      const privateKeyEncrypted = this.certStore!.isPrivateKeyEncrypted(
        cert.serialNumber
      );

      certsWithStatus.push({
        domain: cert.domain,
        domains: cert.domains,
        serialNumber: cert.serialNumber,
        challengeType: cert.challengeType,
        issuedAt: cert.issuedAt,
        expiresAt: cert.expiresAt,
        daysUntilExpiry,
        needsRenewal: cert.expiresAt < renewalThreshold,
        renewalTask,
        privateKeyEncrypted,
      });
    }

    const domainConfigs = this.config.domains || [];
    const domainsStatus = domainConfigs.map((dc) => {
      const primaryDomain = dc.domains[0];
      const cert = certsWithStatus.find((c) => c.domain === primaryDomain) || null;
      const effectiveChallengeType = resolveChallengeType(
        dc.domains,
        dc.challengeType
      );
      return {
        domain: primaryDomain,
        certificate: cert,
        challengeType: effectiveChallengeType,
        autoRenewal: true,
      };
    });

    for (const cert of certsWithStatus) {
      if (!domainConfigs.find((dc) => dc.domains[0] === cert.domain)) {
        domainsStatus.push({
          domain: cert.domain,
          certificate: cert,
          challengeType: cert.challengeType,
          autoRenewal: false,
        });
      }
    }

    const tlsStats = this.tlsTermination?.getStats() || {
      totalTlsHandshakes: 0,
      successfulHandshakes: 0,
      failedHandshakes: 0,
      sniMatches: 0,
      sniFallbackCount: 0,
      sniMismatchCount: 0,
      cachedContextHits: 0,
      cachedContextMisses: 0,
      httpRequestsForwarded: 0,
      httpsRequestsForwarded: 0,
      httpRedirects: 0,
      challengesServed: 0,
      activeConnections: 0,
    };

    const renewalSchedulerStatus = this.renewalScheduler?.getStatus() || {
      isRunning: false,
      isProcessing: false,
      activeTasks: 0,
      pendingTasks: 0,
      completedTasks: 0,
      failedTasks: 0,
      checkIntervalMs: this.config.renewal?.checkIntervalMs ?? 12 * 60 * 60 * 1000,
      renewBeforeDays: this.config.renewal?.renewBeforeDays ?? 30,
      retryDelayMs: this.config.renewal?.retryDelayMs ?? 5 * 60 * 1000,
      maxRetries: this.config.renewal?.maxRetries ?? 10,
    };

    const renewalTasks = this.renewalScheduler?.getRenewalTasks() || [];

    return {
      initialized: this.isInitialized,
      started: this.isStarted,
      storage: this.certStore!.getStorageStats(),
      certificates: certsWithStatus,
      renewalScheduler: {
        isRunning: renewalSchedulerStatus.isRunning,
        isProcessing: renewalSchedulerStatus.isProcessing,
        checkIntervalMs: renewalSchedulerStatus.checkIntervalMs,
        renewBeforeDays: renewalSchedulerStatus.renewBeforeDays,
        retryDelayMs: renewalSchedulerStatus.retryDelayMs,
        maxRetries: renewalSchedulerStatus.maxRetries,
        tasks: renewalTasks,
      },
      tls: {
        httpPort: this.tlsTermination?.getConfig().httpPort ?? 80,
        httpsPort: this.tlsTermination?.getConfig().httpsPort ?? 443,
        defaultDomain: this.tlsTermination?.getDefaultDomain() ?? null,
        stats: {
          totalTlsHandshakes: tlsStats.totalTlsHandshakes,
          successfulHandshakes: tlsStats.successfulHandshakes,
          failedHandshakes: tlsStats.failedHandshakes,
          cachedContextHits: tlsStats.cachedContextHits,
          cachedContextMisses: tlsStats.cachedContextMisses,
          httpRedirects: tlsStats.httpRedirects,
          challengesServed: tlsStats.challengesServed,
          activeConnections: tlsStats.activeConnections,
        },
      },
      domains: domainsStatus,
    };
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

export default AcmeTlsManager;
