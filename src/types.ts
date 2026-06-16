import * as crypto from 'crypto';

export interface AcmeKeyPair {
  publicKey: string;
  privateKey: string;
}

export interface AcmeAccount {
  id?: string;
  keyPair: AcmeKeyPair;
  contact?: string[];
  termsOfServiceAgreed?: boolean;
  status?: 'valid' | 'deactivated' | 'revoked';
}

export interface AcmeDirectory {
  newNonce: string;
  newAccount: string;
  newOrder: string;
  newAuthz: string;
  revokeCert: string;
  keyChange: string;
  directoryMeta?: AcmeDirectoryMeta;
  [key: string]: any;
}

export interface AcmeDirectoryMeta {
  termsOfService?: string;
  website?: string;
  caaIdentities?: string[];
  externalAccountRequired?: boolean;
}

export interface AcmeOrder {
  id?: string;
  status: 'pending' | 'ready' | 'processing' | 'valid' | 'invalid';
  identifiers: AcmeIdentifier[];
  authorizations: string[];
  finalize: string;
  certificate?: string;
  expires?: string;
  error?: AcmeError;
}

export interface AcmeIdentifier {
  type: 'dns';
  value: string;
}

export interface AcmeAuthorization {
  identifier: AcmeIdentifier;
  status: 'pending' | 'valid' | 'invalid' | 'deactivated' | 'expired' | 'revoked';
  expires?: string;
  challenges: AcmeChallenge[];
  wildcard?: boolean;
}

export interface AcmeChallenge {
  type: 'http-01' | 'dns-01' | 'tls-alpn-01';
  url: string;
  token: string;
  status?: 'pending' | 'processing' | 'valid' | 'invalid';
  validated?: string;
  error?: AcmeError;
}

export interface AcmeError {
  type: string;
  detail: string;
  status?: number;
  identifier?: AcmeIdentifier;
  subproblems?: AcmeError[];
}

export interface ChallengeToken {
  token: string;
  keyAuthorization: string;
  domain: string;
  type: 'http-01' | 'dns-01';
  expiresAt: Date;
}

export interface StoredCertificate {
  domain: string;
  domains: string[];
  certificate: string;
  privateKey: string;
  chain: string;
  fullchain: string;
  serialNumber: string;
  issuedAt: Date;
  expiresAt: Date;
  issuer: string;
  challengeType: ChallengeType;
}

export interface RenewalConfig {
  renewBeforeDays: number;
  checkIntervalMs: number;
  retryDelayMs: number;
  maxRetries: number;
}

export interface RenewalPolicy {
  dnsProvider?: DnsProvider;
  onBeforeRenewal?: (cert: StoredCertificate) => Promise<void>;
  onRenewalSuccess?: (
    oldCert: StoredCertificate,
    newCert: StoredCertificate
  ) => Promise<void>;
  onRenewalError?: (
    cert: StoredCertificate,
    error: Error,
    attempt: number
  ) => Promise<void>;
}

export interface TLSTerminationConfig {
  httpPort: number;
  httpsPort: number;
  defaultDomain?: string;
  challengePort: number;
}

export interface DnsProvider {
  name: string;
  addTxtRecord(domain: string, value: string): Promise<void>;
  removeTxtRecord(domain: string, value: string): Promise<void>;
}

export type ChallengeType = 'http-01' | 'dns-01';

export interface RenewalTask {
  domain: string;
  status: 'pending' | 'running' | 'success' | 'failed';
  attempts: number;
  lastError?: string;
  lastAttemptAt?: Date;
  nextAttemptAt?: Date;
  completedAt?: Date;
  lastSuccessAt?: Date;
  lastIssuedSerial?: string;
  consecutiveFailures: number;
  lastIssuanceAt?: Date;
  lastFailureSummary?: {
    beforeSuccessCount: number;
    lastError: string;
    lastFailedAt: Date;
    totalFailuresBeforeSuccess: number;
  };
  failureHistory: Array<{
    error: string;
    timestamp: Date;
    attempt: number;
  }>;
  successHistory: Array<{
    timestamp: Date;
    serialNumber: string;
    daysUntilExpiry: number;
  }>;
  currentPhase?: 'idle' | 'checking' | 'ordering' | 'challenging' | 'finalizing' | 'downloading' | 'installing' | 'cleaning';
  phaseDetail?: string;
  phaseTimeline: Array<{
    phase: RenewalTask['currentPhase'];
    startedAt: Date;
    endedAt?: Date;
    durationMs?: number;
    error?: string;
    detail?: string;
  }>;
}

export type OperationType = 'initial-issue' | 'renewal' | 'manual-request' | 'force-renewal';

export interface DomainOperationRecord {
  type: OperationType;
  startedAt: Date;
  completedAt?: Date;
  status: 'running' | 'success' | 'failed';
  error?: string;
  serialNumber?: string;
  challengeType: ChallengeType;
  phase?: RenewalTask['currentPhase'];
  phaseDetail?: string;
  phaseTimeline: Array<{
    phase: RenewalTask['currentPhase'];
    startedAt: Date;
    endedAt?: Date;
    durationMs?: number;
    error?: string;
    detail?: string;
  }>;
}

export interface DomainLifecycleStatus {
  domain: string;
  configuredDomains: string[];
  effectiveChallengeType: ChallengeType;
  hasWildcard: boolean;
  autoRenewal: boolean;
  lastOperation: {
    type?: OperationType;
    status?: 'running' | 'success' | 'failed';
    startedAt?: Date;
    completedAt?: Date;
    error?: string;
    serialNumber?: string;
  };
  lastSuccessfulIssue?: {
    at: Date;
    serialNumber: string;
    expiresAt: Date;
  };
  lastRenewalAttempt?: {
    at: Date;
    success: boolean;
    error?: string;
  };
  lastFailure?: {
    at: Date;
    error: string;
    operationType?: OperationType;
    phase?: RenewalTask['currentPhase'];
  };
  nextScheduledRenewalAt?: Date;
  consecutiveRenewalFailures: number;
  totalRenewalAttempts: number;
  successfulRenewals: number;
  currentState:
    | 'unissued'
    | 'issuing'
    | 'issuing-failed'
    | 'active'
    | 'renewing'
    | 'renewal-failed'
    | 'expiring-soon'
    | 'expired';
  stateReason?: string;
  latestOperations: DomainOperationRecord[];
  renewalTask?: RenewalTask;
}

export interface CertificateRenewalStatus {
  domain: string;
  domains: string[];
  serialNumber: string;
  challengeType: ChallengeType;
  issuedAt: Date;
  expiresAt: Date;
  daysUntilExpiry: number;
  needsRenewal: boolean;
  renewalTask?: RenewalTask;
  privateKeyEncrypted: boolean;
}

export interface HealthCheckResult {
  healthy: boolean;
  timestamp: Date;
  uptimeMs: number;
  components: {
    manager: {
      healthy: boolean;
      initialized: boolean;
      started: boolean;
    };
    httpChallenge: {
      healthy: boolean;
      port: number;
      available: boolean;
      detail?: string;
    };
    httpsDefaultCert: {
      healthy: boolean;
      port: number;
      hasDefaultCert: boolean;
      defaultDomain: string | null;
      expiresAt?: Date;
      daysUntilExpiry?: number;
      serialNumber?: string;
      detail?: string;
    };
    renewalScheduler: {
      healthy: boolean;
      isRunning: boolean;
      anyConsecutiveFailures: boolean;
      maxConsecutiveFailures: number;
      failedDomains: string[];
      detail?: string;
    };
    storage: {
      healthy: boolean;
      storageDir: string;
      writable: boolean;
      totalCertificates: number;
      detail?: string;
    };
    canary?: {
      healthy: boolean;
      active: boolean;
      canaryDomains: string[];
      canarySerialNumber: string | null;
      baselineSerialNumber: string | null;
      successCount: number;
      failureCount: number;
      readyToPromote: boolean;
      readyToRollback: boolean;
    };
  };
  summary: string[];
  warnings: string[];
  criticals: string[];
}

export interface ManagedServiceStatus {
  initialized: boolean;
  started: boolean;
  storage: {
    totalCertificates: number;
    managedDomains: number;
    storageDir: string;
  };
  certificates: CertificateRenewalStatus[];
  renewalScheduler: {
    isRunning: boolean;
    isProcessing: boolean;
    checkIntervalMs: number;
    renewBeforeDays: number;
    retryDelayMs: number;
    maxRetries: number;
    tasks: RenewalTask[];
  };
  tls: {
    httpPort: number;
    httpsPort: number;
    defaultDomain: string | null;
    defaultSerialNumber: string | null;
    canaryStatus?: CanaryStatus;
    stats: {
      totalTlsHandshakes: number;
      successfulHandshakes: number;
      failedHandshakes: number;
      sniMatches: number;
      sniFallbackCount: number;
      sniMismatchCount: number;
      cachedContextHits: number;
      cachedContextMisses: number;
      canaryHits: number;
      canaryMisses: number;
      httpRedirects: number;
      challengesServed: number;
      activeConnections: number;
    };
  };
  domains: DomainLifecycleStatus[];
}

export interface RenewalHistoryEntry {
  domain: string;
  timestamp: Date;
  type: 'success' | 'failure';
  attempt: number;
  serialNumber?: string;
  daysUntilExpiry?: number;
  error?: string;
}

export interface DomainRenewalHistory {
  domain: string;
  entries: RenewalHistoryEntry[];
  summary: {
    totalSuccesses: number;
    totalFailures: number;
    consecutiveFailures: number;
    lastSuccessAt?: Date;
    lastFailureAt?: Date;
    lastFailureError?: string;
  };
}

export interface CanaryResult {
  domain: string;
  serialNumber: string;
  timestamp: Date;
  success: boolean;
  tlsVersion?: string;
  cipher?: string;
  error?: string;
  peerCertSerial?: string;
  peerCertSubject?: Record<string, string>;
  peerCertIssuer?: Record<string, string>;
  peerCertSubjectCN?: string;
  peerCertIssuerCN?: string;
  peerCertValidFrom?: Date;
  peerCertValidTo?: Date;
}

export interface CanaryStatus {
  active: boolean;
  canaryDomains: string[];
  canarySerialNumber: string | null;
  canaryCertExpiresAt?: Date;
  baselineSerialNumber: string | null;
  baselineCertExpiresAt?: Date;
  canaryInstalledAt?: Date | null;
  results: CanaryResult[];
  successCount: number;
  failureCount: number;
  readyToPromote: boolean;
  readyToRollback: boolean;
}

export interface CertificateStorageConfig {
  storageDir: string;
  encryptPrivateKeys?: boolean;
  encryptionPassphrase?: string;
  filePermissions?: number;
}

export interface AcmeClientConfig {
  directoryUrl: string;
  accountKeyPath?: string;
  contact?: string[];
  agreeToTerms?: boolean;
}

export interface CertificateRequest {
  domains: string[];
  challengeType: ChallengeType;
  dnsProvider?: DnsProvider;
}

export const LETSENCRYPT_STAGING_DIRECTORY =
  'https://acme-staging-v02.api.letsencrypt.org/directory';
export const LETSENCRYPT_PRODUCTION_DIRECTORY =
  'https://acme-v02.api.letsencrypt.org/directory';
