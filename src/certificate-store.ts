import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { StoredCertificate, CertificateStorageConfig } from './types';
import * as forge from 'node-forge';

const DEFAULT_FILE_PERMISSIONS = 0o600;
const DEFAULT_DIR_PERMISSIONS = 0o700;

export class CertificateStore {
  private config: Required<CertificateStorageConfig>;
  private certCache: Map<string, StoredCertificate> = new Map();
  private domainIndex: Map<string, string> = new Map();
  private indexFilePath: string;
  private encryptionKey: Buffer | null = null;

  constructor(config: CertificateStorageConfig) {
    this.config = {
      storageDir: config.storageDir,
      encryptPrivateKeys: config.encryptPrivateKeys ?? false,
      encryptionPassphrase: config.encryptionPassphrase ?? '',
      filePermissions: config.filePermissions ?? DEFAULT_FILE_PERMISSIONS,
    };

    this.indexFilePath = path.join(this.config.storageDir, 'index.json');

    if (this.config.encryptPrivateKeys && this.config.encryptionPassphrase) {
      this.encryptionKey = this.deriveKeyFromPassphrase(
        this.config.encryptionPassphrase,
        Buffer.alloc(16)
      );
    }
  }

  private deriveKeyFromPassphrase(passphrase: string, salt: Buffer): Buffer {
    return crypto.pbkdf2Sync(passphrase, salt, 100000, 32, 'sha256');
  }

  private encryptPrivateKey(privateKeyPem: string): string {
    if (!this.encryptionKey) {
      return privateKeyPem;
    }

    const salt = crypto.randomBytes(16);
    const key = this.deriveKeyFromPassphrase(this.config.encryptionPassphrase, salt);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

    const encrypted = Buffer.concat([
      cipher.update(Buffer.from(privateKeyPem, 'utf8')),
      cipher.final(),
    ]);

    const authTag = cipher.getAuthTag();

    const result = {
      v: 2,
      salt: salt.toString('base64'),
      iv: iv.toString('base64'),
      tag: authTag.toString('base64'),
      data: encrypted.toString('base64'),
    };

    return `-----BEGIN ENCRYPTED PRIVATE KEY-----\n${Buffer.from(
      JSON.stringify(result),
      'utf8'
    ).toString('base64')}\n-----END ENCRYPTED PRIVATE KEY-----`;
  }

  private decryptPrivateKey(encryptedKeyPem: string): string {
    if (!encryptedKeyPem.includes('BEGIN ENCRYPTED PRIVATE KEY')) {
      return encryptedKeyPem;
    }

    try {
      const base64Content = encryptedKeyPem
        .replace(/-----BEGIN ENCRYPTED PRIVATE KEY-----\n?/, '')
        .replace(/-----END ENCRYPTED PRIVATE KEY-----\n?/, '')
        .replace(/\n/g, '');

      const jsonContent = Buffer.from(base64Content, 'base64').toString('utf8');
      const parsed = JSON.parse(jsonContent);

      const salt = Buffer.from(parsed.salt, 'base64');
      const iv = Buffer.from(parsed.iv, 'base64');
      const tag = Buffer.from(parsed.tag, 'base64');
      const data = Buffer.from(parsed.data, 'base64');

      let key: Buffer;
      if (parsed.v === 2 && this.config.encryptionPassphrase) {
        key = this.deriveKeyFromPassphrase(this.config.encryptionPassphrase, salt);
      } else if (this.encryptionKey) {
        key = this.encryptionKey;
      } else if (this.config.encryptionPassphrase) {
        key = this.deriveKeyFromPassphrase(this.config.encryptionPassphrase, salt);
      } else {
        throw new Error('No decryption key available');
      }

      const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        key,
        iv
      );
      decipher.setAuthTag(tag);

      const decrypted = Buffer.concat([
        decipher.update(data),
        decipher.final(),
      ]);

      return decrypted.toString('utf8');
    } catch (err) {
      throw new Error(
        `Failed to decrypt private key: ${(err as Error).message}`
      );
    }
  }

  async initialize(): Promise<void> {
    await this.ensureDir(this.config.storageDir);
    await this.loadIndex();
    await this.loadAllCertificates();
  }

  private async ensureDir(dir: string): Promise<void> {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, {
        recursive: true,
        mode: DEFAULT_DIR_PERMISSIONS,
      });
    }
  }

  private safeWrite(filePath: string, content: string | Buffer): void {
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true, mode: DEFAULT_DIR_PERMISSIONS });
    }

    const tempPath = `${filePath}.tmp`;
    fs.writeFileSync(tempPath, content, {
      mode: this.config.filePermissions,
    });

    fs.renameSync(tempPath, filePath);

    try {
      fs.chmodSync(filePath, this.config.filePermissions);
    } catch {
      // Some filesystems don't support chmod
    }
  }

  private async loadIndex(): Promise<void> {
    if (!fs.existsSync(this.indexFilePath)) {
      this.saveIndex();
      return;
    }

    try {
      const data = fs.readFileSync(this.indexFilePath, 'utf8');
      const index = JSON.parse(data);
      if (index.domainIndex) {
        for (const [domain, serial] of Object.entries(index.domainIndex)) {
          this.domainIndex.set(domain, serial as string);
        }
      }
    } catch (err) {
      console.warn(
        `[CertificateStore] Failed to load index, rebuilding: ${(err as Error).message}`
      );
      this.saveIndex();
    }
  }

  private saveIndex(): void {
    const index = {
      domainIndex: Object.fromEntries(this.domainIndex.entries()),
      updatedAt: new Date().toISOString(),
    };
    this.safeWrite(this.indexFilePath, JSON.stringify(index, null, 2));
  }

  private async loadAllCertificates(): Promise<void> {
    const certsDir = path.join(this.config.storageDir, 'certs');
    if (!fs.existsSync(certsDir)) {
      return;
    }

    const entries = fs.readdirSync(certsDir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isDirectory()) {
        const serial = entry.name;
        const certDataPath = path.join(certsDir, serial, 'cert.json');
        if (fs.existsSync(certDataPath)) {
          try {
            const data = fs.readFileSync(certDataPath, 'utf8');
            const parsed = JSON.parse(data);
            const storedCert: StoredCertificate = {
              ...parsed,
              issuedAt: new Date(parsed.issuedAt),
              expiresAt: new Date(parsed.expiresAt),
            };
            this.certCache.set(serial, storedCert);
          } catch (err) {
            console.warn(
              `[CertificateStore] Failed to load certificate ${serial}: ${(err as Error).message}`
            );
          }
        }
      }
    }
  }

  async saveCertificate(cert: StoredCertificate): Promise<void> {
    const certDir = path.join(this.config.storageDir, 'certs', cert.serialNumber);

    const storedPrivateKey = this.config.encryptPrivateKeys
      ? this.encryptPrivateKey(cert.privateKey)
      : cert.privateKey;

    this.safeWrite(path.join(certDir, 'cert.pem'), cert.certificate);
    this.safeWrite(path.join(certDir, 'chain.pem'), cert.chain);
    this.safeWrite(path.join(certDir, 'fullchain.pem'), cert.fullchain);
    this.safeWrite(path.join(certDir, 'privkey.pem'), storedPrivateKey);

    const certMeta: Omit<StoredCertificate, 'privateKey'> & {
      privateKeyEncrypted: boolean;
    } = {
      domain: cert.domain,
      domains: cert.domains,
      certificate: cert.certificate,
      chain: cert.chain,
      fullchain: cert.fullchain,
      serialNumber: cert.serialNumber,
      issuedAt: cert.issuedAt,
      expiresAt: cert.expiresAt,
      issuer: cert.issuer,
      challengeType: cert.challengeType,
      privateKeyEncrypted: this.config.encryptPrivateKeys,
    };

    this.safeWrite(
      path.join(certDir, 'cert.json'),
      JSON.stringify(certMeta, null, 2)
    );

    this.certCache.set(cert.serialNumber, cert);

    for (const domain of cert.domains) {
      this.domainIndex.set(domain, cert.serialNumber);
    }

    this.saveIndex();

    console.log(
      `[CertificateStore] Saved certificate for ${cert.domains.join(', ')} (serial: ${cert.serialNumber})`
    );
  }

  async getCertificateByDomain(
    domain: string
  ): Promise<StoredCertificate | null> {
    const serial = this.domainIndex.get(domain);
    if (!serial) {
      const wildcardDomain = `*.${domain.split('.').slice(1).join('.')}`;
      const wildcardSerial = this.domainIndex.get(wildcardDomain);
      if (!wildcardSerial) {
        return null;
      }
      return this.getCertificateBySerial(wildcardSerial);
    }

    return this.getCertificateBySerial(serial);
  }

  async getCertificateBySerial(
    serialNumber: string
  ): Promise<StoredCertificate | null> {
    const cached = this.certCache.get(serialNumber);
    if (!cached) {
      return null;
    }

    return {
      ...cached,
    };
  }

  async getPrivateKeyForSerial(serialNumber: string): Promise<string | null> {
    const cert = this.certCache.get(serialNumber);
    if (!cert) {
      return null;
    }

    const privKeyPath = path.join(
      this.config.storageDir,
      'certs',
      serialNumber,
      'privkey.pem'
    );

    if (!fs.existsSync(privKeyPath)) {
      return null;
    }

    const content = fs.readFileSync(privKeyPath, 'utf8');

    if (content.includes('BEGIN ENCRYPTED PRIVATE KEY')) {
      return this.decryptPrivateKey(content);
    }

    return content;
  }

  async getTlsContextForDomain(
    domain: string
  ): Promise<{ cert: string; key: string; ca?: string } | null> {
    const cert = await this.getCertificateByDomain(domain);
    if (!cert) {
      return null;
    }

    const key = await this.getPrivateKeyForSerial(cert.serialNumber);
    if (!key) {
      return null;
    }

    return {
      cert: cert.fullchain,
      key,
      ca: cert.chain || undefined,
    };
  }

  async getAllCertificates(): Promise<StoredCertificate[]> {
    return Array.from(this.certCache.values()).map((c) => ({ ...c }));
  }

  async getDomainsNeedingRenewal(renewBeforeDays: number): Promise<
    Array<{
      cert: StoredCertificate;
      daysUntilExpiry: number;
    }>
  > {
    const now = new Date();
    const threshold = new Date(
      now.getTime() + renewBeforeDays * 24 * 60 * 60 * 1000
    );

    const result: Array<{
      cert: StoredCertificate;
      daysUntilExpiry: number;
    }> = [];

    for (const cert of this.certCache.values()) {
      if (cert.expiresAt < threshold) {
        const daysUntilExpiry = Math.ceil(
          (cert.expiresAt.getTime() - now.getTime()) / (24 * 60 * 60 * 1000)
        );
        result.push({ cert, daysUntilExpiry });
      }
    }

    return result.sort(
      (a, b) => a.daysUntilExpiry - b.daysUntilExpiry
    );
  }

  async removeCertificate(serialNumber: string): Promise<void> {
    const cert = this.certCache.get(serialNumber);
    if (!cert) {
      return;
    }

    for (const domain of cert.domains) {
      if (this.domainIndex.get(domain) === serialNumber) {
        this.domainIndex.delete(domain);
      }
    }

    this.certCache.delete(serialNumber);

    const certDir = path.join(this.config.storageDir, 'certs', serialNumber);
    if (fs.existsSync(certDir)) {
      fs.rmSync(certDir, { recursive: true, force: true });
    }

    this.saveIndex();

    console.log(
      `[CertificateStore] Removed certificate ${serialNumber}`
    );
  }

  getManagedDomains(): string[] {
    return Array.from(this.domainIndex.keys());
  }

  getStorageStats(): {
    totalCertificates: number;
    managedDomains: number;
    storageDir: string;
  } {
    return {
      totalCertificates: this.certCache.size,
      managedDomains: this.domainIndex.size,
      storageDir: this.config.storageDir,
    };
  }

  parseCertificateInfo(certPem: string): {
    serialNumber: string;
    issuedAt: Date;
    expiresAt: Date;
    issuer: string;
    domains: string[];
    thumbprint: string;
  } {
    const cert = forge.pki.certificateFromPem(certPem);

    const domains: string[] = [];
    const cn = cert.subject.getField('CN');
    if (cn && cn.value) {
      domains.push(cn.value as string);
    }

    const sanExtension = cert.getExtension('subjectAltName');
    if (sanExtension) {
      for (const altName of (sanExtension as any).altNames || []) {
        if (altName.type === 2 && altName.value) {
          domains.push(altName.value);
        }
      }
    }

    const issuerParts = cert.issuer.attributes.map(
      (attr) => `${attr.shortName}=${attr.value}`
    );
    const issuer = issuerParts.join(', ');

    const der = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
    const thumbprintBuffer = crypto
      .createHash('sha256')
      .update(Buffer.from(der, 'binary'))
      .digest('hex');

    return {
      serialNumber: cert.serialNumber.toUpperCase(),
      issuedAt: cert.validity.notBefore,
      expiresAt: cert.validity.notAfter,
      issuer,
      domains: [...new Set(domains)],
      thumbprint: thumbprintBuffer,
    };
  }
}
