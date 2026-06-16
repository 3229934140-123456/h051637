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
