import * as fs from 'fs';
import * as path from 'path';
import {
  AcmeChallenge,
  ChallengeType,
  DnsProvider,
  RenewalConfig,
  RenewalPolicy,
  StoredCertificate,
  RenewalTask,
} from './types';
import { AcmeClient } from './acme-client';
import { CertificateStore } from './certificate-store';
import { ChallengeResponder } from './challenge-responder';

export { RenewalTask };

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
  private tasksFilePath: string;

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
    this.tasksFilePath = path.join(
      (this.certStore as any).config.storageDir,
      'renewal-tasks.json'
    );
  }

  start(): void {
    if (this.isRunning) {
      return;
    }

    this.isRunning = true;

    this.loadTasksFromDisk();

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
      `[RenewalScheduler] Started (check interval: ${this.config.checkIntervalMs / 1000}s, renew before: ${this.config.renewBeforeDays} days, max retries: ${this.config.maxRetries})`
    );
  }

  private loadTasksFromDisk(): void {
    try {
      if (fs.existsSync(this.tasksFilePath)) {
        const data = fs.readFileSync(this.tasksFilePath, 'utf8');
        const parsed = JSON.parse(data);
        if (Array.isArray(parsed.tasks)) {
          for (const taskData of parsed.tasks) {
            const task: RenewalTask = {
              ...taskData,
              lastAttemptAt: taskData.lastAttemptAt
                ? new Date(taskData.lastAttemptAt)
                : undefined,
              nextAttemptAt: taskData.nextAttemptAt
                ? new Date(taskData.nextAttemptAt)
                : undefined,
              completedAt: taskData.completedAt
                ? new Date(taskData.completedAt)
                : undefined,
              failureHistory: (taskData.failureHistory || []).map(
                (h: any) => ({
                  ...h,
                  timestamp: new Date(h.timestamp),
                })
              ),
            };
            if (task.status === 'running') {
              task.status = 'failed';
            }
            this.tasks.set(task.domain, task);
          }
          console.log(
            `[RenewalScheduler] Loaded ${this.tasks.size} renewal task(s) from disk`
          );
        }
      }
    } catch (err) {
      console.warn(
        `[RenewalScheduler] Failed to load tasks from disk: ${(err as Error).message}`
      );
    }
  }

  private saveTasksToDisk(): void {
    try {
      const tasksData = Array.from(this.tasks.values()).map((task) => ({
        ...task,
        failureHistory: (task.failureHistory || []).slice(-10),
      }));
      const data = {
        version: 1,
        updatedAt: new Date().toISOString(),
        tasks: tasksData,
      };
      fs.writeFileSync(
        this.tasksFilePath,
        JSON.stringify(data, null, 2),
        'utf8'
      );
    } catch (err) {
      console.warn(
        `[RenewalScheduler] Failed to save tasks to disk: ${(err as Error).message}`
      );
    }
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.saveTasksToDisk();
    this.isRunning = false;
    console.log('[RenewalScheduler] Stopped');
  }

  async forceRenewal(domain: string): Promise<void> {
    const cert = await this.certStore.getCertificateByDomain(domain);
    if (cert) {
      const task = this.tasks.get(domain);
      if (task) {
        task.attempts = 0;
        task.nextAttemptAt = new Date();
        task.failureHistory = [];
        this.tasks.set(domain, task);
        this.saveTasksToDisk();
      }
      await this.renewCertificate(cert);
    }
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
          `[RenewalScheduler] Renewing ${domain} (expires in ${daysUntilExpiry} days, challenge: ${cert.challengeType})`
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
    const effectiveChallengeType = resolveChallengeType(
      cert.domains,
      cert.challengeType
    );

    if (
      hasWildcardDomain(cert.domains) &&
      cert.challengeType !== 'dns-01'
    ) {
      console.warn(
        `[RenewalScheduler] Domain ${domain} has wildcard(s), forcing DNS-01 challenge (original: ${cert.challengeType})`
      );
    }

    const existingTask = this.tasks.get(domain);
    const task: RenewalTask = {
      domain,
      status: 'running',
      attempts: (existingTask?.attempts || 0) + 1,
      lastAttemptAt: new Date(),
      failureHistory: existingTask?.failureHistory || [],
    };

    this.tasks.set(domain, task);
    this.saveTasksToDisk();

    const activeTokens: Array<{
      type: ChallengeType;
      token: string;
      keyAuth: string;
      domain: string;
    }> = [];

    try {
      if (this.policy.onBeforeRenewal) {
        await this.policy.onBeforeRenewal(cert);
      }

      const result = await this.acmeClient.issueCertificate(
        {
          domains: cert.domains,
          challengeType: effectiveChallengeType,
          dnsProvider: this.policy.dnsProvider,
        },
        async (
          challenge: AcmeChallenge,
          keyAuthorization: string,
          challengeDomain: string
        ) => {
          await this.challengeResponder.registerChallenge(
            effectiveChallengeType,
            challenge.token,
            keyAuthorization,
            challengeDomain
          );
          activeTokens.push({
            type: effectiveChallengeType,
            token: challenge.token,
            keyAuth: keyAuthorization,
            domain: challengeDomain,
          });

          if (effectiveChallengeType === 'http-01') {
            await this.sleep(1000);
          } else if (effectiveChallengeType === 'dns-01') {
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
        challengeType: effectiveChallengeType,
      };

      await this.certStore.saveCertificate(newCert);

      if (this.policy.onRenewalSuccess) {
        await this.policy.onRenewalSuccess(cert, newCert);
      }

      await this.certStore.removeCertificate(cert.serialNumber);

      task.status = 'success';
      task.completedAt = new Date();
      task.lastError = undefined;
      task.nextAttemptAt = undefined;
      task.failureHistory = [];

      console.log(
        `[RenewalScheduler] Successfully renewed ${domain} with ${effectiveChallengeType} (serial: ${newCert.serialNumber})`
      );
    } catch (err) {
      const error = err as Error;

      for (const token of activeTokens) {
        try {
          await this.challengeResponder.unregisterChallenge(
            token.type,
            token.token,
            token.keyAuth,
            token.domain
          );
        } catch (cleanupErr) {
          console.warn(
            `[RenewalScheduler] Failed to cleanup challenge after error: ${(cleanupErr as Error).message}`
          );
        }
      }

      task.status = 'failed';
      task.lastError = error.message;
      task.nextAttemptAt = new Date(
        Date.now() +
          this.config.retryDelayMs * Math.pow(2, task.attempts - 1)
      );
      task.failureHistory = [
        ...(task.failureHistory || []),
        {
          error: error.message,
          timestamp: new Date(),
          attempt: task.attempts,
        },
      ].slice(-10);

      if (this.policy.onRenewalError) {
        await this.policy.onRenewalError(cert, error, task.attempts);
      }

      console.error(
        `[RenewalScheduler] Renewal failed for ${domain} (attempt ${task.attempts}/${this.config.maxRetries}): ${error.message}. Next retry at ${task.nextAttemptAt.toISOString()}`
      );

      throw err;
    } finally {
      this.tasks.set(domain, { ...task });
      this.saveTasksToDisk();
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
    retryDelayMs: number;
    maxRetries: number;
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
      retryDelayMs: this.config.retryDelayMs,
      maxRetries: this.config.maxRetries,
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
