import {
  AcmeChallenge,
  ChallengeType,
  DnsProvider,
  RenewalConfig,
  RenewalPolicy,
  StoredCertificate,
} from './types';
import { AcmeClient } from './acme-client';
import { CertificateStore } from './certificate-store';
import { ChallengeResponder } from './challenge-responder';

export interface RenewalTask {
  domain: string;
  status: 'pending' | 'running' | 'success' | 'failed';
  attempts: number;
  lastError?: string;
  lastAttemptAt?: Date;
  nextAttemptAt?: Date;
  completedAt?: Date;
}

export class RenewalScheduler {
  private acmeClient: AcmeClient;
  private certStore: CertificateStore;
  private challengeResponder: ChallengeResponder;
  private config: Required<RenewalConfig>;
  private policy: RenewalPolicy;
  private timer: NodeJS.Timeout | null = null;
  private tasks: Map<string, RenewalTask> = new Map();
  private isRunning: boolean = false;
  private isProcessing: boolean = false;
  private forcedRenewals: Set<string> = new Set();

  constructor(
    acmeClient: AcmeClient,
    certStore: CertificateStore,
    challengeResponder: ChallengeResponder,
    config: Partial<RenewalConfig>,
    policy: RenewalPolicy
  ) {
    this.acmeClient = acmeClient;
    this.certStore = certStore;
    this.challengeResponder = challengeResponder;
    this.config = {
      renewBeforeDays: config.renewBeforeDays ?? 30,
      checkIntervalMs: config.checkIntervalMs ?? 12 * 60 * 60 * 1000,
      retryDelayMs: config.retryDelayMs ?? 5 * 60 * 1000,
      maxRetries: config.maxRetries ?? 10,
    };
    this.policy = policy;
  }

  start(): void {
    if (this.isRunning) {
      return;
    }

    this.isRunning = true;

    this.checkAndRenewAll().catch((err) => {
      console.error(
        `[RenewalScheduler] Initial check failed: ${err.message}`
      );
    });

    this.timer = setInterval(() => {
      this.checkAndRenewAll().catch((err) => {
        console.error(
          `[RenewalScheduler] Periodic check failed: ${err.message}`
        );
      });
    }, this.config.checkIntervalMs);

    console.log(
      `[RenewalScheduler] Started (check interval: ${this.config.checkIntervalMs / 1000}s, renew before: ${this.config.renewBeforeDays} days)`
    );
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.isRunning = false;
    console.log('[RenewalScheduler] Stopped');
  }

  async forceRenewal(domain: string): Promise<void> {
    this.forcedRenewals.add(domain);
    const cert = await this.certStore.getCertificateByDomain(domain);
    if (cert) {
      await this.renewCertificate(cert);
    }
    this.forcedRenewals.delete(domain);
  }

  private async checkAndRenewAll(): Promise<void> {
    if (this.isProcessing) {
      console.log('[RenewalScheduler] Check already in progress, skipping');
      return;
    }

    this.isProcessing = true;

    try {
      const needingRenewal = await this.certStore.getDomainsNeedingRenewal(
        this.config.renewBeforeDays
      );

      console.log(
        `[RenewalScheduler] Found ${needingRenewal.length} certificate(s) needing renewal`
      );

      for (const { cert, daysUntilExpiry } of needingRenewal) {
        const domain = cert.domain;

        const task = this.tasks.get(domain);

        if (task && task.status === 'running') {
          continue;
        }

        if (task && task.status === 'failed') {
          if (task.nextAttemptAt && new Date() < task.nextAttemptAt) {
            continue;
          }
          if (task.attempts >= this.config.maxRetries) {
            console.warn(
              `[RenewalScheduler] Max retries (${this.config.maxRetries}) reached for ${domain}, giving up`
            );
            continue;
          }
        }

        console.log(
          `[RenewalScheduler] Renewing ${domain} (expires in ${daysUntilExpiry} days)`
        );

        try {
          await this.renewCertificate(cert);
        } catch (err) {
          console.error(
            `[RenewalScheduler] Renewal failed for ${domain}: ${(err as Error).message}`
          );
        }
      }
    } finally {
      this.isProcessing = false;
    }
  }

  private async renewCertificate(cert: StoredCertificate): Promise<void> {
    const domain = cert.domain;
    const task: RenewalTask = {
      domain,
      status: 'running',
      attempts: (this.tasks.get(domain)?.attempts || 0) + 1,
      lastAttemptAt: new Date(),
    };

    this.tasks.set(domain, task);

    try {
      if (this.policy.onBeforeRenewal) {
        await this.policy.onBeforeRenewal(cert);
      }

      const activeTokens: Array<{
        type: ChallengeType;
        token: string;
        keyAuth: string;
        domain: string;
      }> = [];

      const result = await this.acmeClient.issueCertificate(
        {
          domains: cert.domains,
          challengeType: this.policy.challengeType,
          dnsProvider: this.policy.dnsProvider,
        },
        async (
          challenge: AcmeChallenge,
          keyAuthorization: string,
          challengeDomain: string
        ) => {
          await this.challengeResponder.registerChallenge(
            this.policy.challengeType,
            challenge.token,
            keyAuthorization,
            challengeDomain
          );
          activeTokens.push({
            type: this.policy.challengeType,
            token: challenge.token,
            keyAuth: keyAuthorization,
            domain: challengeDomain,
          });

          if (this.policy.challengeType === 'http-01') {
            await this.sleep(1000);
          } else if (this.policy.challengeType === 'dns-01') {
            await this.sleep(5000);
          }
        }
      );

      for (const token of activeTokens) {
        try {
          await this.challengeResponder.unregisterChallenge(
            token.type,
            token.token,
            token.keyAuth,
            token.domain
          );
        } catch (err) {
          console.warn(
            `[RenewalScheduler] Failed to unregister challenge: ${(err as Error).message}`
          );
        }
      }

      const certInfo = this.certStore.parseCertificateInfo(result.certificate);

      const newCert: StoredCertificate = {
        domain: cert.domains[0],
        domains: cert.domains,
        certificate: result.certificate,
        chain: result.chain,
        fullchain: result.fullchain,
        privateKey: result.privateKey,
        serialNumber: certInfo.serialNumber,
        issuedAt: certInfo.issuedAt,
        expiresAt: certInfo.expiresAt,
        issuer: certInfo.issuer,
      };

      await this.certStore.removeCertificate(cert.serialNumber);
      await this.certStore.saveCertificate(newCert);

      task.status = 'success';
      task.completedAt = new Date();

      if (this.policy.onRenewalSuccess) {
        await this.policy.onRenewalSuccess(cert, newCert);
      }

      console.log(
        `[RenewalScheduler] Successfully renewed ${domain} (serial: ${newCert.serialNumber})`
      );
    } catch (err) {
      const error = err as Error;
      task.status = 'failed';
      task.lastError = error.message;
      task.nextAttemptAt = new Date(
        Date.now() +
          this.config.retryDelayMs * Math.pow(2, task.attempts - 1)
      );

      if (this.policy.onRenewalError) {
        await this.policy.onRenewalError(cert, error, task.attempts);
      }

      throw err;
    } finally {
      this.tasks.set(domain, { ...task });
    }
  }

  getRenewalTasks(): RenewalTask[] {
    return Array.from(this.tasks.values());
  }

  getTaskForDomain(domain: string): RenewalTask | undefined {
    return this.tasks.get(domain);
  }

  getStatus(): {
    isRunning: boolean;
    isProcessing: boolean;
    activeTasks: number;
    pendingTasks: number;
    completedTasks: number;
    failedTasks: number;
    checkIntervalMs: number;
    renewBeforeDays: number;
  } {
    const tasks = Array.from(this.tasks.values());
    return {
      isRunning: this.isRunning,
      isProcessing: this.isProcessing,
      activeTasks: tasks.filter((t) => t.status === 'running').length,
      pendingTasks: tasks.filter((t) => t.status === 'pending').length,
      completedTasks: tasks.filter((t) => t.status === 'success').length,
      failedTasks: tasks.filter((t) => t.status === 'failed').length,
      checkIntervalMs: this.config.checkIntervalMs,
      renewBeforeDays: this.config.renewBeforeDays,
    };
  }

  async runImmediateCheck(): Promise<
    Array<{
      domain: string;
      daysUntilExpiry: number;
      needsRenewal: boolean;
    }>
  > {
    const allCerts = await this.certStore.getAllCertificates();
    const now = new Date();
    const threshold = new Date(
      now.getTime() + this.config.renewBeforeDays * 24 * 60 * 60 * 1000
    );

    return allCerts
      .map((cert) => {
        const daysUntilExpiry = Math.ceil(
          (cert.expiresAt.getTime() - now.getTime()) / (24 * 60 * 60 * 1000)
        );
        return {
          domain: cert.domain,
          daysUntilExpiry,
          needsRenewal: cert.expiresAt < threshold,
        };
      })
      .sort((a, b) => a.daysUntilExpiry - b.daysUntilExpiry);
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
