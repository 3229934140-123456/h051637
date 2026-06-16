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
      };
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

    if (this.tlsTermination) {
      defaultDomain = this.tlsTermination.getDefaultDomain();
      if (defaultDomain) {
        const cert = await this.certStore!.getCertificateByDomain(defaultDomain);
        if (cert) {
          hasDefaultCert = true;
          defaultCertExpiry = cert.expiresAt;
          defaultCertDays = Math.ceil(
            (cert.expiresAt.getTime() - now.getTime()) / (24 * 60 * 60 * 1000)
          );
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
      detail: hasDefaultCert
        ? defaultCertDays && defaultCertDays > minDays
          ? `Default certificate for ${defaultDomain} valid for ${defaultCertDays} day(s)`
          : `Default certificate for ${defaultDomain} expires in ${defaultCertDays} day(s) (threshold: ${minDays})`
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
      },
      summary,
      warnings,
      criticals,
    };
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
