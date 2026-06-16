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
  DomainLifecycleStatus,
  HealthCheckResult,
  DomainRenewalHistory,
  DomainOperationRecord,
  OperationType,
  CanaryResult,
  CanaryStatus,
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
  private startTime: number = 0;
  private operationLog: Map<string, DomainOperationRecord[]> = new Map();
  private operationLogLimit: number = 5;

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
    this.startTime = Date.now();

    console.log('[AcmeTlsManager] Started successfully');
  }

  private recordOperation(
    primaryDomain: string,
    type: OperationType,
    update: Partial<DomainOperationRecord>
  ): void {
    let logs = this.operationLog.get(primaryDomain);
    if (!logs) {
      logs = [];
      this.operationLog.set(primaryDomain, logs);
    }

    if (update.status === 'running') {
      const record: DomainOperationRecord = {
        type,
        startedAt: new Date(),
        status: 'running',
        challengeType: update.challengeType || 'http-01',
        phase: update.phase,
        phaseTimeline: [],
      };
      if (update.phaseTimeline) {
        record.phaseTimeline = update.phaseTimeline;
      } else if (update.phase) {
        record.phaseTimeline = [
          { phase: update.phase, startedAt: new Date(), detail: update.phaseDetail },
        ];
      }
      logs.unshift(record);
    } else {
      const current = logs.find((r) => r.status === 'running' && r.type === type);
      if (current) {
        Object.assign(current, {
          ...update,
          completedAt: new Date(),
        });
      } else {
        const record: DomainOperationRecord = {
          type,
          startedAt: new Date(Date.now() - 1),
          completedAt: new Date(),
          status: update.status || 'success',
          challengeType: update.challengeType || 'http-01',
          error: update.error,
          serialNumber: update.serialNumber,
          phase: update.phase,
          phaseTimeline: update.phaseTimeline || [],
        };
        logs.unshift(record);
      }
    }

    if (logs.length > this.operationLogLimit) {
      logs.length = this.operationLogLimit;
    }
  }

  private getLatestOperations(primaryDomain: string): DomainOperationRecord[] {
    return this.operationLog.get(primaryDomain) || [];
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
        this.recordOperation(primaryDomain, 'initial-issue', {
          status: 'running',
          challengeType: resolveChallengeType(
            domainConfig.domains,
            domainConfig.challengeType
          ),
          phase: 'ordering',
        });

        await this.requestCertificate({
          domains: domainConfig.domains,
          challengeType: resolveChallengeType(
            domainConfig.domains,
            domainConfig.challengeType
          ),
          dnsProvider: this.config.challenge?.dnsProvider,
        });
      } catch (err) {
        const error = err as Error;
        this.recordOperation(primaryDomain, 'initial-issue', {
          status: 'failed',
          error: error.message,
          challengeType: resolveChallengeType(
            domainConfig.domains,
            domainConfig.challengeType
          ),
        });
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
        this.tlsTermination!.invalidateContextCacheForDomains(newCert.domains);

        const defaultDomain = this.tlsTermination!.getDefaultDomain();
        if (defaultDomain && newCert.domains.includes(defaultDomain)) {
          this.tlsTermination!.setDefaultDomain(defaultDomain);
        }

        await this.sleep(1000);

        let probeSuccess = false;
        if (defaultDomain && newCert.domains.includes(defaultDomain)) {
          const probe = await this.probeDefaultCertificate();
          probeSuccess = probe.success && probe.actualSerial === newCert.serialNumber;
          if (probeSuccess) {
            console.log(
              `[AcmeTlsManager] Probe confirmed: default domain ${defaultDomain} now uses serial ${probe.actualSerial}`
            );
          } else {
            console.warn(
              `[AcmeTlsManager] Probe failed: expected ${newCert.serialNumber}, got ${probe.actualSerial || probe.error}`
            );
          }
        } else {
          probeSuccess = true;
        }

        if (probeSuccess) {
          await this.certStore!.removeCertificate(oldCert.serialNumber);
          console.log(
            `[AcmeTlsManager] Old certificate removed: ${oldCert.domain} (serial: ${oldCert.serialNumber})`
          );
        } else {
          console.warn(
            `[AcmeTlsManager] Keeping old certificate ${oldCert.serialNumber} as fallback due to probe failure`
          );
        }

        this.recordOperation(newCert.domain, 'renewal', {
          status: 'success',
          serialNumber: newCert.serialNumber,
          challengeType: newCert.challengeType,
          phase: 'idle',
        });
      },
      onRenewalError: async (cert: StoredCertificate, error: Error, attempt: number) => {
        console.error(
          `[AcmeTlsManager] Renewal attempt ${attempt} failed for ${cert.domain}: ${error.message}`
        );
        this.recordOperation(cert.domain, 'renewal', {
          status: 'failed',
          error: error.message,
          challengeType: cert.challengeType,
        });
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

    const primaryDomain = request.domains[0];
    const opType: OperationType = existingCert ? 'manual-request' : 'initial-issue';

    try {
      this.recordOperation(primaryDomain, opType, {
        status: 'running',
        challengeType: effectiveChallengeType,
        phase: 'ordering',
      });

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
        this.tlsTermination.invalidateContextCacheForDomains(request.domains);
        const currentDefault = this.tlsTermination.getDefaultDomain();
        if (currentDefault && request.domains.includes(currentDefault)) {
          this.tlsTermination.setDefaultDomain(request.domains[0]);
        }
      }

      let oldCertRemoved = false;
      if (existingCert && existingCert.serialNumber !== storedCert.serialNumber) {
        await this.certStore!.removeCertificate(existingCert.serialNumber);
        oldCertRemoved = true;
        console.log(
          `[AcmeTlsManager] Removed old certificate for ${storedCert.domain} (serial: ${existingCert.serialNumber})`
        );
      }

      this.recordOperation(primaryDomain, opType, {
        status: 'success',
        serialNumber: storedCert.serialNumber,
        challengeType: effectiveChallengeType,
        phase: 'idle',
      });

      console.log(
        `[AcmeTlsManager] Certificate issued for ${request.domains.join(', ')} with ${effectiveChallengeType} (expires ${storedCert.expiresAt.toISOString()}, old cert removed: ${oldCertRemoved})`
      );

      return storedCert;
    } catch (err) {
      const error = err as Error;

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

      this.recordOperation(primaryDomain, opType, {
        status: 'failed',
        error: error.message,
        challengeType: effectiveChallengeType,
      });

      throw err;
    }
  }

  async forceRenewal(domain: string): Promise<void> {
    if (!this.renewalScheduler) {
      throw new Error('Renewal scheduler not started');
    }
    this.recordOperation(domain, 'force-renewal', {
      status: 'running',
      challengeType: 'dns-01',
      phase: 'checking',
    });
    try {
      await this.renewalScheduler.forceRenewal(domain);
      this.recordOperation(domain, 'force-renewal', {
        status: 'success',
        challengeType: 'dns-01',
        phase: 'idle',
      });
    } catch (err) {
      const error = err as Error;
      this.recordOperation(domain, 'force-renewal', {
        status: 'failed',
        error: error.message,
        challengeType: 'dns-01',
      });
      throw err;
    }
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
    const primaryToCert = new Map<string, CertificateRenewalStatus>();
    for (const cs of certsWithStatus) {
      primaryToCert.set(cs.domain, cs);
    }

    const domainsStatus: DomainLifecycleStatus[] = domainConfigs.map((dc) => {
      const primaryDomain = dc.domains[0];
      const hasWildcard = hasWildcardDomain(dc.domains);
      const effectiveChallengeType = resolveChallengeType(
        dc.domains,
        dc.challengeType
      );
      const certStatus = primaryToCert.get(primaryDomain);
      const latestOps = this.getLatestOperations(primaryDomain);
      const renewalTask = this.renewalScheduler?.getTaskForDomain(primaryDomain);

      const lastOperation: DomainLifecycleStatus['lastOperation'] = {};
      const lastOp = latestOps[0];
      if (lastOp) {
        lastOperation.type = lastOp.type;
        lastOperation.status = lastOp.status;
        lastOperation.startedAt = lastOp.startedAt;
        lastOperation.completedAt = lastOp.completedAt;
        lastOperation.error = lastOp.error;
        lastOperation.serialNumber = lastOp.serialNumber;
      }

      let lastSuccessfulIssue: DomainLifecycleStatus['lastSuccessfulIssue'] = undefined;
      const lastSuccess = latestOps.find((o) => o.status === 'success');
      if (lastSuccess && lastSuccess.serialNumber && certStatus) {
        lastSuccessfulIssue = {
          at: lastSuccess.completedAt || lastSuccess.startedAt,
          serialNumber: lastSuccess.serialNumber,
          expiresAt: certStatus.expiresAt,
        };
      }

      let lastRenewalAttempt: DomainLifecycleStatus['lastRenewalAttempt'] = undefined;
      const lastRenewal = latestOps.find((o) => o.type === 'renewal');
      if (lastRenewal) {
        lastRenewalAttempt = {
          at: lastRenewal.completedAt || lastRenewal.startedAt,
          success: lastRenewal.status === 'success',
          error: lastRenewal.error,
        };
      }

      let lastFailure: DomainLifecycleStatus['lastFailure'] = undefined;
      const lastFailed = latestOps.find((o) => o.status === 'failed');
      if (lastFailed) {
        lastFailure = {
          at: lastFailed.completedAt || lastFailed.startedAt,
          error: lastFailed.error || 'Unknown error',
          operationType: lastFailed.type,
          phase: lastFailed.phase,
        };
      }

      const consecutiveRenewalFailures = renewalTask?.consecutiveFailures || 0;
      const totalRenewalAttempts =
        (renewalTask?.successHistory.length || 0) +
        (renewalTask?.failureHistory.length || 0);
      const successfulRenewals = renewalTask?.successHistory.length || 0;

      let currentState: DomainLifecycleStatus['currentState'];
      let stateReason: string | undefined;

      if (!certStatus) {
        const running = latestOps.find((o) => o.status === 'running');
        const failed = latestOps.find((o) => o.status === 'failed');
        if (running) {
          currentState = 'issuing';
          stateReason = `Issuing in progress at phase: ${running.phase || 'unknown'}`;
        } else if (failed) {
          currentState = 'issuing-failed';
          stateReason = `Last issue failed: ${failed.error || 'unknown error'}`;
        } else {
          currentState = 'unissued';
          stateReason = 'Certificate has not been issued yet';
        }
      } else if (
        renewalTask?.status === 'running' ||
        (lastOperation?.status === 'running' && lastOperation?.type === 'renewal')
      ) {
        currentState = 'renewing';
        stateReason = `Renewal in progress at phase: ${renewalTask?.currentPhase || lastOperation?.type || 'unknown'}`;
      } else if (certStatus.daysUntilExpiry <= 0) {
        currentState = 'expired';
        stateReason = `Certificate expired ${Math.abs(certStatus.daysUntilExpiry)} day(s) ago`;
      } else if (certStatus.needsRenewal) {
        if (consecutiveRenewalFailures > 0) {
          currentState = 'renewal-failed';
          stateReason = `Renewal failed ${consecutiveRenewalFailures} time(s). Last error: ${renewalTask?.lastError || 'unknown'}`;
        } else {
          currentState = 'expiring-soon';
          stateReason = `Certificate will expire in ${certStatus.daysUntilExpiry} day(s), needs renewal`;
        }
      } else {
        currentState = 'active';
        stateReason = `Certificate valid for ${certStatus.daysUntilExpiry} more day(s)`;
      }

      return {
        domain: primaryDomain,
        configuredDomains: dc.domains,
        effectiveChallengeType,
        hasWildcard,
        autoRenewal: true,
        lastOperation,
        lastSuccessfulIssue,
        lastRenewalAttempt,
        lastFailure,
        nextScheduledRenewalAt: renewalTask?.nextAttemptAt,
        consecutiveRenewalFailures,
        totalRenewalAttempts,
        successfulRenewals,
        currentState,
        stateReason,
        latestOperations: latestOps,
        renewalTask,
      };
    });

    for (const cs of certsWithStatus) {
      if (!domainConfigs.find((dc) => dc.domains[0] === cs.domain)) {
        const renewalTask = this.renewalScheduler?.getTaskForDomain(cs.domain);
        domainsStatus.push({
          domain: cs.domain,
          configuredDomains: cs.domains,
          effectiveChallengeType: cs.challengeType,
          hasWildcard: hasWildcardDomain(cs.domains),
          autoRenewal: false,
          lastOperation: {},
          lastSuccessfulIssue: {
            at: cs.issuedAt,
            serialNumber: cs.serialNumber,
            expiresAt: cs.expiresAt,
          },
          nextScheduledRenewalAt: renewalTask?.nextAttemptAt,
          consecutiveRenewalFailures: renewalTask?.consecutiveFailures || 0,
          totalRenewalAttempts:
            (renewalTask?.successHistory.length || 0) +
            (renewalTask?.failureHistory.length || 0),
          successfulRenewals: renewalTask?.successHistory.length || 0,
          currentState: cs.daysUntilExpiry <= 0 ? 'expired' : 'active',
          stateReason: `Auto-renewal disabled. Valid for ${cs.daysUntilExpiry} day(s)`,
          latestOperations: this.getLatestOperations(cs.domain),
          renewalTask,
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
      canaryHits: 0,
      canaryMisses: 0,
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
    const defaultSerial = this.tlsTermination
      ? await this.tlsTermination.getDefaultCertificateSerial()
      : null;
    const canaryStatus = this.tlsTermination?.getCanaryStatus() || null;

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
        defaultSerialNumber: defaultSerial,
        canaryStatus: canaryStatus ?? undefined,
        stats: {
          totalTlsHandshakes: tlsStats.totalTlsHandshakes,
          successfulHandshakes: tlsStats.successfulHandshakes,
          failedHandshakes: tlsStats.failedHandshakes,
          cachedContextHits: tlsStats.cachedContextHits,
          cachedContextMisses: tlsStats.cachedContextMisses,
          sniMatches: tlsStats.sniMatches,
          sniFallbackCount: tlsStats.sniFallbackCount,
          sniMismatchCount: tlsStats.sniMismatchCount,
          canaryHits: tlsStats.canaryHits,
          canaryMisses: tlsStats.canaryMisses,
          httpRedirects: tlsStats.httpRedirects,
          challengesServed: tlsStats.challengesServed,
          activeConnections: tlsStats.activeConnections,
        },
      },
      domains: domainsStatus,
    };
  }

  async getHealthCheck(
    options: {
      consecutiveFailureThreshold?: number;
      minDaysRemaining?: number;
    } = {}
  ): Promise<HealthCheckResult> {
    if (!this.isInitialized) {
      await this.initialize();
    }

    const now = new Date();
    const uptimeMs = this.startTime > 0 ? now.getTime() - this.startTime : 0;
    const warnings: string[] = [];
    const criticals: string[] = [];
    const summary: string[] = [];

    const managerHealthy = this.isInitialized && this.isStarted;
    if (!this.isInitialized) {
      criticals.push('Manager not initialized');
    } else if (!this.isStarted) {
      warnings.push('Manager initialized but not started');
    } else {
      summary.push('Manager initialized and started');
    }

    let httpPort = this.config.tls?.httpPort ?? 80;
    let httpsPort = this.config.tls?.httpsPort ?? 443;
    if (this.tlsTermination) {
      const cfg = this.tlsTermination.getConfig();
      httpPort = cfg.httpPort;
      httpsPort = cfg.httpsPort;
    }

    const httpChallengeHealthy = this.tlsTermination
      ? (this.tlsTermination as any).httpServer?.listening ?? false
      : false;
    const httpChallenge: HealthCheckResult['components']['httpChallenge'] = {
      healthy: httpChallengeHealthy,
      port: httpPort,
      available: httpChallengeHealthy,
      detail: httpChallengeHealthy
        ? `HTTP challenge server listening on port ${httpPort}`
        : `HTTP challenge server not listening on port ${httpPort}`,
    };
    if (httpChallengeHealthy) {
      summary.push(`HTTP challenge server available on port ${httpPort}`);
    } else {
      criticals.push(`HTTP challenge server unavailable on port ${httpPort}`);
    }

    let defaultDomain: string | null = null;
    let hasDefaultCert = false;
    let defaultCertExpiry: Date | undefined;
    let defaultCertDays: number | undefined;
    let defaultCertSerial: string | undefined;

    if (this.tlsTermination) {
      defaultDomain = this.tlsTermination.getDefaultDomain();
      const serial = await this.tlsTermination.getDefaultCertificateSerial();
      defaultCertSerial = serial ?? undefined;
      if (defaultDomain) {
        const cert = await this.certStore!.getCertificateByDomain(defaultDomain);
        if (cert) {
          hasDefaultCert = true;
          defaultCertExpiry = cert.expiresAt;
          defaultCertDays = Math.ceil(
            (cert.expiresAt.getTime() - now.getTime()) / (24 * 60 * 60 * 1000)
          );
          defaultCertSerial = cert.serialNumber;
        }
      }
    }

    const minDays = options.minDaysRemaining ?? 14;
    const defaultCertHealthy =
      hasDefaultCert && (defaultCertDays ?? 0) > minDays;

    const httpsDefaultCert: HealthCheckResult['components']['httpsDefaultCert'] = {
      healthy: defaultCertHealthy,
      port: httpsPort,
      hasDefaultCert,
      defaultDomain,
      expiresAt: defaultCertExpiry,
      daysUntilExpiry: defaultCertDays,
      serialNumber: defaultCertSerial,
      detail: hasDefaultCert
        ? defaultCertDays && defaultCertDays > minDays
          ? `Default certificate for ${defaultDomain} valid for ${defaultCertDays} day(s) (serial: ${defaultCertSerial})`
          : `Default certificate for ${defaultDomain} expires in ${defaultCertDays} day(s) (threshold: ${minDays}, serial: ${defaultCertSerial})`
        : defaultDomain
          ? `No certificate found for default domain ${defaultDomain}`
          : 'No default domain configured',
    };
    if (!hasDefaultCert) {
      criticals.push(`No default HTTPS certificate available`);
    } else if (defaultCertDays !== undefined && defaultCertDays <= minDays) {
      warnings.push(`Default certificate expiring soon: ${defaultCertDays} day(s) left`);
    } else {
      summary.push(`Default HTTPS certificate OK for ${defaultDomain}`);
    }

    const consecutiveThreshold = options.consecutiveFailureThreshold ?? 3;
    const consecutiveFailures = this.renewalScheduler
      ? this.renewalScheduler.getConsecutiveFailures()
      : [];
    const anyConsecutiveFailures =
      consecutiveFailures.some((f) => f.consecutiveFailures >= consecutiveThreshold);
    const failedDomains = consecutiveFailures
      .filter((f) => f.consecutiveFailures >= 2)
      .map((f) => f.domain);
    const schedulerRunning = this.renewalScheduler?.getStatus().isRunning ?? false;

    const maxConsecutive =
      consecutiveFailures.length > 0 ? consecutiveFailures[0].consecutiveFailures : 0;

    const renewalScheduler: HealthCheckResult['components']['renewalScheduler'] = {
      healthy: schedulerRunning && !anyConsecutiveFailures,
      isRunning: schedulerRunning,
      anyConsecutiveFailures,
      maxConsecutiveFailures: maxConsecutive,
      failedDomains,
      detail: schedulerRunning
        ? anyConsecutiveFailures
          ? `${consecutiveFailures.filter((f) => f.consecutiveFailures >= consecutiveThreshold).length} domain(s) have >= ${consecutiveThreshold} consecutive renewal failures`
          : failedDomains.length > 0
            ? `${failedDomains.length} domain(s) with 2+ consecutive failures (under threshold ${consecutiveThreshold})`
            : 'Scheduler running, no excessive consecutive failures'
        : 'Renewal scheduler not running',
    };

    if (!schedulerRunning) {
      criticals.push('Renewal scheduler not running');
    } else if (anyConsecutiveFailures) {
      criticals.push(`Renewal consecutive failures detected (>= ${consecutiveThreshold}): ${failedDomains.join(', ')}`);
    } else if (failedDomains.length > 0) {
      warnings.push(`Some domains have consecutive renewal failures: ${failedDomains.join(', ')}`);
    } else {
      summary.push('Renewal scheduler healthy');
    }

    let storageWritable = false;
    const storageDir = (this.certStore as any).config.storageDir || './acme-data';
    try {
      const testFile = require('path').join(storageDir, '.healthcheck.tmp');
      require('fs').writeFileSync(testFile, String(Date.now()));
      require('fs').unlinkSync(testFile);
      storageWritable = true;
    } catch {
      storageWritable = false;
    }
    const storageStats = this.certStore!.getStorageStats();
    const storageHealthy = storageWritable;

    const storage: HealthCheckResult['components']['storage'] = {
      healthy: storageHealthy,
      storageDir,
      writable: storageWritable,
      totalCertificates: storageStats.totalCertificates,
      detail: storageWritable
        ? `Storage OK at ${storageDir}: ${storageStats.totalCertificates} cert(s) managing ${storageStats.managedDomains} domain(s)`
        : `Storage directory not writable at ${storageDir}`,
    };
    if (storageWritable) {
      summary.push(`Storage writable at ${storageDir}`);
    } else {
      criticals.push(`Storage directory not writable at ${storageDir}`);
    }

    const healthy =
      managerHealthy &&
      httpChallengeHealthy &&
      defaultCertHealthy &&
      renewalScheduler.healthy &&
      storageHealthy;

    const canary = this.tlsTermination?.getCanaryStatus() || null;
    const canaryHealthy =
      canary && canary.active
        ? !canary.readyToRollback
        : true;

    return {
      healthy,
      timestamp: now,
      uptimeMs,
      components: {
        manager: {
          healthy: managerHealthy,
          initialized: this.isInitialized,
          started: this.isStarted,
        },
        httpChallenge,
        httpsDefaultCert,
        renewalScheduler,
        storage,
        canary: canary
          ? {
              healthy: canaryHealthy,
              active: canary.active,
              canaryDomains: canary.canaryDomains,
              canarySerialNumber: canary.canarySerialNumber,
              baselineSerialNumber: canary.baselineSerialNumber,
              successCount: canary.successCount,
              failureCount: canary.failureCount,
              readyToPromote: canary.readyToPromote,
              readyToRollback: canary.readyToRollback,
            }
          : undefined,
      },
      summary,
      warnings,
      criticals,
    };
  }

  async startCanary(options: {
    domains: string[];
    canarySerialNumber: string;
    baselineSerialNumber?: string;
  }): Promise<CanaryStatus> {
    if (!this.isInitialized) {
      await this.initialize();
    }

    if (!this.tlsTermination) {
      throw new Error('TLS termination not initialized');
    }

    let baselineSerial: string | undefined = options.baselineSerialNumber;
    if (!baselineSerial) {
      const serial = await this.tlsTermination.getDefaultCertificateSerial();
      baselineSerial = serial ?? undefined;
    }

    if (!baselineSerial) {
      throw new Error('Could not determine baseline certificate serial number');
    }

    this.tlsTermination.setCanaryConfig({
      canaryDomains: options.domains,
      canarySerialNumber: options.canarySerialNumber,
      baselineSerialNumber: baselineSerial,
    });

    return this.getCanaryStatus();
  }

  async probeCanary(domain: string): Promise<CanaryResult> {
    if (!this.tlsTermination) {
      throw new Error('TLS termination not initialized');
    }
    return this.tlsTermination.probeCanary(domain);
  }

  getCanaryStatus(): CanaryStatus {
    if (!this.tlsTermination) {
      return {
        active: false,
        canaryDomains: [],
        canarySerialNumber: null,
        baselineSerialNumber: null,
        successCount: 0,
        failureCount: 0,
        readyToPromote: false,
        readyToRollback: false,
        results: [],
      };
    }
    const s = this.tlsTermination.getCanaryStatus();
    return {
      active: s.active,
      canaryDomains: s.canaryDomains,
      canarySerialNumber: s.canarySerialNumber,
      baselineSerialNumber: s.baselineSerialNumber,
      successCount: s.successCount,
      failureCount: s.failureCount,
      readyToPromote: s.readyToPromote,
      readyToRollback: s.readyToRollback,
      results: s.results,
    };
  }

  async promoteCanary(): Promise<CanaryStatus> {
    if (!this.tlsTermination) {
      throw new Error('TLS termination not initialized');
    }

    const status = this.getCanaryStatus();
    if (!status.active && !status.readyToPromote) {
      console.warn(
        `[AcmeTlsManager] Promoting canary but not ready (${status.successCount} success, ${status.failureCount} failures)`
      );
    }

    this.tlsTermination.promoteCanary();

    const canarySerial = status.canarySerialNumber;
    const baselineSerial = status.baselineSerialNumber;

    if (canarySerial && baselineSerial && canarySerial !== baselineSerial) {
      const defaultDomain = this.tlsTermination.getDefaultDomain();
      if (defaultDomain) {
        const cert = await this.certStore!.getCertificateByDomain(defaultDomain);
        if (cert && cert.serialNumber === canarySerial) {
          this.tlsTermination.setDefaultDomain(defaultDomain);
        }
      }

      await this.sleep(1000);

      const probeResult = await this.probeDefaultCertificate();
      if (probeResult.success && probeResult.actualSerial !== canarySerial) {
        console.warn(
          `[AcmeTlsManager] Promoted but probe shows serial ${probeResult.actualSerial}, expected ${canarySerial}`
        );
      }
    }

    return this.getCanaryStatus();
  }

  async rollbackCanary(): Promise<CanaryStatus> {
    if (!this.tlsTermination) {
      throw new Error('TLS termination not initialized');
    }

    const status = this.getCanaryStatus();

    if (!status.active) {
      throw new Error('No canary deployment active');
    }

    this.tlsTermination.rollbackCanary();

    return this.getCanaryStatus();
  }

  async probeDefaultCertificate(): Promise<{
    success: boolean;
    domain: string | null;
    expectedSerial: string | null;
    actualSerial?: string;
    actualSubject?: string;
    actualIssuer?: string;
    validTo?: Date;
    error?: string;
  }> {
    if (!this.tlsTermination) {
      return {
        success: false,
        domain: null,
        expectedSerial: null,
        error: 'TLS termination not initialized',
      };
    }
    return this.tlsTermination.probeDefaultCertificate();
  }

  async getPrometheusMetrics(): Promise<string> {
    if (!this.isInitialized) {
      await this.initialize();
    }

    const lines: string[] = [];
    const now = Date.now();

    lines.push('# HELP acme_manager_info ACME TLS manager info');
    lines.push('# TYPE acme_manager_info gauge');
    lines.push(
      `acme_manager_info{version="1.0.0",initialized="${this.isInitialized}",started="${this.isStarted}"} 1`
    );

    if (this.startTime > 0) {
      const uptimeSeconds = Math.floor((now - this.startTime) / 1000);
      lines.push('# HELP acme_manager_uptime_seconds Uptime of the manager in seconds');
      lines.push('# TYPE acme_manager_uptime_seconds gauge');
      lines.push(`acme_manager_uptime_seconds ${uptimeSeconds}`);
    }

    const allCerts = await this.certStore!.getAllCertificates();
    lines.push('# HELP acme_certificate_days_remaining Days remaining until certificate expiry');
    lines.push('# TYPE acme_certificate_days_remaining gauge');

    for (const cert of allCerts) {
      const daysRemaining = Math.max(
        0,
        Math.ceil(
          (cert.expiresAt.getTime() - now) / (24 * 60 * 60 * 1000)
        )
      );
      const domainLabel = cert.domain.replace(/"/g, '\\"');
      const serialLabel = cert.serialNumber.replace(/"/g, '\\"');
      lines.push(
        `acme_certificate_days_remaining{domain="${domainLabel}",serial="${serialLabel}",issuer="${cert.issuer.replace(/"/g, '\\"')}"} ${daysRemaining}`
      );
    }

    lines.push('# HELP acme_certificate_expires_at_timestamp Unix timestamp when certificate expires');
    lines.push('# TYPE acme_certificate_expires_at_timestamp gauge');
    for (const cert of allCerts) {
      const domainLabel = cert.domain.replace(/"/g, '\\"');
      const serialLabel = cert.serialNumber.replace(/"/g, '\\"');
      lines.push(
        `acme_certificate_expires_at_timestamp{domain="${domainLabel}",serial="${serialLabel}"} ${Math.floor(cert.expiresAt.getTime() / 1000)}`
      );
    }

    lines.push('# HELP acme_certificate_info Information about managed certificates');
    lines.push('# TYPE acme_certificate_info gauge');
    for (const cert of allCerts) {
      const domainLabel = cert.domain.replace(/"/g, '\\"');
      const serialLabel = cert.serialNumber.replace(/"/g, '\\"');
      const issuerLabel = cert.issuer.replace(/"/g, '\\"');
      const challengeType = cert.challengeType || 'unknown';
      lines.push(
        `acme_certificate_info{domain="${domainLabel}",serial="${serialLabel}",issuer="${issuerLabel}",challenge_type="${challengeType}"} 1`
      );
    }

    const consecutiveFailures = this.renewalScheduler
      ? this.renewalScheduler.getConsecutiveFailures()
      : [];

    lines.push('# HELP acme_renewal_consecutive_failures Consecutive renewal failures per domain');
    lines.push('# TYPE acme_renewal_consecutive_failures gauge');
    for (const cf of consecutiveFailures) {
      const domainLabel = cf.domain.replace(/"/g, '\\"');
      lines.push(
        `acme_renewal_consecutive_failures{domain="${domainLabel}"} ${cf.consecutiveFailures}`
      );
    }

    const renewalTasks = this.renewalScheduler?.getRenewalTasks() || [];

    lines.push('# HELP acme_renewal_task_status Status of renewal tasks');
    lines.push('# TYPE acme_renewal_task_status gauge');
    for (const task of renewalTasks) {
      const domainLabel = task.domain.replace(/"/g, '\\"');
      const statusLabel = task.status;
      lines.push(
        `acme_renewal_task_status{domain="${domainLabel}",status="${statusLabel}"} 1`
      );
    }

    lines.push('# HELP acme_renewal_task_attempts Total renewal attempts per domain');
    lines.push('# TYPE acme_renewal_task_attempts counter');
    for (const task of renewalTasks) {
      const domainLabel = task.domain.replace(/"/g, '\\"');
      lines.push(
        `acme_renewal_task_attempts{domain="${domainLabel}"} ${task.attempts}`
      );
    }

    const tlsStats = this.tlsTermination?.getStats() || null;

    if (tlsStats) {
      lines.push('# HELP acme_tls_handshakes_total Total number of TLS handshake attempts');
      lines.push('# TYPE acme_tls_handshakes_total counter');
      lines.push(`acme_tls_handshakes_total ${tlsStats.totalTlsHandshakes}`);

      lines.push('# HELP acme_tls_handshakes_successful_total Total number of successful TLS handshakes');
      lines.push('# TYPE acme_tls_handshakes_successful_total counter');
      lines.push(`acme_tls_handshakes_successful_total ${tlsStats.successfulHandshakes}`);

      lines.push('# HELP acme_tls_handshakes_failed_total Total number of failed TLS handshakes');
      lines.push('# TYPE acme_tls_handshakes_failed_total counter');
      lines.push(`acme_tls_handshakes_failed_total ${tlsStats.failedHandshakes}`);

      lines.push('# HELP acme_tls_sni_matches_total Total number of SNI matches');
      lines.push('# TYPE acme_tls_sni_matches_total counter');
      lines.push(`acme_tls_sni_matches_total ${tlsStats.sniMatches}`);

      lines.push('# HELP acme_tls_sni_fallback_total Total number of SNI fallback to default certificate');
      lines.push('# TYPE acme_tls_sni_fallback_total counter');
      lines.push(`acme_tls_sni_fallback_total ${tlsStats.sniFallbackCount}`);

      lines.push('# HELP acme_tls_sni_mismatch_total Total number of SNI mismatch errors');
      lines.push('# TYPE acme_tls_sni_mismatch_total counter');
      lines.push(`acme_tls_sni_mismatch_total ${tlsStats.sniMismatchCount}`);

      lines.push('# HELP acme_tls_context_cache_hits_total Total number of TLS context cache hits');
      lines.push('# TYPE acme_tls_context_cache_hits_total counter');
      lines.push(`acme_tls_context_cache_hits_total ${tlsStats.cachedContextHits}`);

      lines.push('# HELP acme_tls_context_cache_misses_total Total number of TLS context cache misses');
      lines.push('# TYPE acme_tls_context_cache_misses_total counter');
      lines.push(`acme_tls_context_cache_misses_total ${tlsStats.cachedContextMisses}`);

      lines.push('# HELP acme_tls_canary_hits_total Total number of canary routing hits');
      lines.push('# TYPE acme_tls_canary_hits_total counter');
      lines.push(`acme_tls_canary_hits_total ${tlsStats.canaryHits}`);

      lines.push('# HELP acme_tls_canary_misses_total Total number of canary routing misses');
      lines.push('# TYPE acme_tls_canary_misses_total counter');
      lines.push(`acme_tls_canary_misses_total ${tlsStats.canaryMisses}`);

      lines.push('# HELP acme_http_redirects_total Total number of HTTP redirects');
      lines.push('# TYPE acme_http_redirects_total counter');
      lines.push(`acme_http_redirects_total ${tlsStats.httpRedirects}`);

      lines.push('# HELP acme_challenges_served_total Total number of ACME challenges served');
      lines.push('# TYPE acme_challenges_served_total counter');
      lines.push(`acme_challenges_served_total ${tlsStats.challengesServed}`);

      lines.push('# HELP acme_tls_active_connections Current number of active TLS connections');
      lines.push('# TYPE acme_tls_active_connections gauge');
      lines.push(`acme_tls_active_connections ${tlsStats.activeConnections}`);
    }

    const canaryStatus = this.tlsTermination?.getCanaryStatus() || null;
    if (canaryStatus && canaryStatus.active) {
      lines.push('# HELP acme_canary_active Whether a canary deployment is active');
      lines.push('# TYPE acme_canary_active gauge');
      lines.push(`acme_canary_active 1`);

      lines.push('# HELP acme_canary_success_count Number of successful canary probes');
      lines.push('# TYPE acme_canary_success_count gauge');
      lines.push(`acme_canary_success_count ${canaryStatus.successCount}`);

      lines.push('# HELP acme_canary_failure_count Number of failed canary probes');
      lines.push('# TYPE acme_canary_failure_count gauge');
      lines.push(`acme_canary_failure_count ${canaryStatus.failureCount}`);

      lines.push('# HELP acme_canary_ready_to_promote Whether canary is ready to promote');
      lines.push('# TYPE acme_canary_ready_to_promote gauge');
      lines.push(`acme_canary_ready_to_promote ${canaryStatus.readyToPromote ? 1 : 0}`);

      lines.push('# HELP acme_canary_ready_to_rollback Whether canary is ready to rollback');
      lines.push('# TYPE acme_canary_ready_to_rollback gauge');
      lines.push(`acme_canary_ready_to_rollback ${canaryStatus.readyToRollback ? 1 : 0}`);
    } else {
      lines.push('# HELP acme_canary_active Whether a canary deployment is active');
      lines.push('# TYPE acme_canary_active gauge');
      lines.push(`acme_canary_active 0`);
    }

    const storageStats = this.certStore!.getStorageStats();
    lines.push('# HELP acme_storage_certificates_total Total number of certificates in storage');
    lines.push('# TYPE acme_storage_certificates_total gauge');
    lines.push(`acme_storage_certificates_total ${storageStats.totalCertificates}`);

    lines.push('# HELP acme_storage_domains_total Total number of managed domains');
    lines.push('# TYPE acme_storage_domains_total gauge');
    lines.push(`acme_storage_domains_total ${storageStats.managedDomains}`);

    return lines.join('\n') + '\n';
  }

  getRenewalHistory(
    domain: string,
    limit: number = 20
  ): DomainRenewalHistory {
    if (!this.renewalScheduler) {
      return {
        domain,
        entries: [],
        summary: {
          totalSuccesses: 0,
          totalFailures: 0,
          consecutiveFailures: 0,
        },
      };
    }
    return this.renewalScheduler.getRenewalHistoryForDomain(domain, limit);
  }

  getAllConsecutiveFailures(): Array<{
    domain: string;
    consecutiveFailures: number;
    lastError: string;
    nextAttemptAt?: Date;
  }> {
    if (!this.renewalScheduler) {
      return [];
    }
    return this.renewalScheduler.getConsecutiveFailures();
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

export default AcmeTlsManager;
