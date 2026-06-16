import * as crypto from 'crypto';
import { ChallengeToken, ChallengeType, DnsProvider } from './types';

export class ChallengeResponder {
  private httpTokens: Map<string, ChallengeToken> = new Map();
  private dnsTokens: Map<string, ChallengeToken> = new Map();
  private dnsProvider: DnsProvider | null = null;

  constructor(dnsProvider?: DnsProvider) {
    this.dnsProvider = dnsProvider || null;
  }

  handleHttpChallengeRequest(
    reqUrl: string
  ): { found: boolean; keyAuthorization?: string; domain?: string } {
    if (!reqUrl.startsWith('/.well-known/acme-challenge/')) {
      return { found: false };
    }

    const token = reqUrl.substring('/.well-known/acme-challenge/'.length);

    const stored = this.httpTokens.get(token);
    if (!stored) {
      return { found: false };
    }

    if (new Date() > stored.expiresAt) {
      this.httpTokens.delete(token);
      return { found: false };
    }

    console.log(
      `[ChallengeResponder] HTTP-01 challenge served for ${stored.domain}: ${token}`
    );

    return { found: true, keyAuthorization: stored.keyAuthorization, domain: stored.domain };
  }

  isChallengePath(url: string): boolean {
    return url.startsWith('/.well-known/acme-challenge/');
  }

  async registerHttpChallenge(
    token: string,
    keyAuthorization: string,
    domain: string,
    ttlSeconds: number = 3600
  ): Promise<void> {
    const challengeToken: ChallengeToken = {
      token,
      keyAuthorization,
      domain,
      type: 'http-01',
      expiresAt: new Date(Date.now() + ttlSeconds * 1000),
    };

    this.httpTokens.set(token, challengeToken);

    console.log(
      `[ChallengeResponder] Registered HTTP-01 challenge for ${domain}: token=${token}`
    );
  }

  async unregisterHttpChallenge(token: string): Promise<void> {
    this.httpTokens.delete(token);
    console.log(`[ChallengeResponder] Unregistered HTTP-01 challenge: token=${token}`);
  }

  async registerDnsChallenge(
    token: string,
    keyAuthorization: string,
    domain: string,
    ttlSeconds: number = 3600
  ): Promise<void> {
    if (!this.dnsProvider) {
      throw new Error(
        'DNS provider not configured. Cannot perform DNS-01 challenge.'
      );
    }

    const sha256 = crypto
      .createHash('sha256')
      .update(keyAuthorization)
      .digest('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');

    const dnsRecordName = `_acme-challenge.${domain}`;

    const challengeToken: ChallengeToken = {
      token,
      keyAuthorization: sha256,
      domain,
      type: 'dns-01',
      expiresAt: new Date(Date.now() + ttlSeconds * 1000),
    };

    this.dnsTokens.set(`${dnsRecordName}:${sha256}`, challengeToken);

    await this.dnsProvider.addTxtRecord(dnsRecordName, sha256);

    await this.waitForDnsPropagation(dnsRecordName, sha256);

    console.log(
      `[ChallengeResponder] Registered DNS-01 challenge for ${domain}: TXT ${dnsRecordName}="${sha256}"`
    );
  }

  private async waitForDnsPropagation(
    recordName: string,
    expectedValue: string,
    timeoutMs: number = 120000,
    checkIntervalMs: number = 5000
  ): Promise<void> {
    const startTime = Date.now();

    while (Date.now() - startTime < timeoutMs) {
      try {
        const records = await this.resolveTxt(recordName);
        if (records.includes(expectedValue)) {
          return;
        }
      } catch {
        // DNS lookup failed, will retry
      }
      await this.sleep(checkIntervalMs);
    }

    console.warn(
      `[ChallengeResponder] DNS propagation timeout for ${recordName}, but continuing anyway`
    );
  }

  private async resolveTxt(domain: string): Promise<string[]> {
    try {
      const { Resolver } = await import('dns');
      return new Promise((resolve, reject) => {
        const resolver = new Resolver();
        resolver.setServers(['8.8.8.8', '1.1.1.1']);
        resolver.resolveTxt(domain, (err, records) => {
          if (err) {
            reject(err);
          } else {
            const result: string[] = [];
            for (const record of records) {
              result.push(record.join(''));
            }
            resolve(result);
          }
        });
      });
    } catch {
      return [];
    }
  }

  async unregisterDnsChallenge(
    domain: string,
    keyAuthorization: string
  ): Promise<void> {
    if (!this.dnsProvider) {
      return;
    }

    const sha256 = crypto
      .createHash('sha256')
      .update(keyAuthorization)
      .digest('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');

    const dnsRecordName = `_acme-challenge.${domain}`;
    const key = `${dnsRecordName}:${sha256}`;

    this.dnsTokens.delete(key);

    try {
      await this.dnsProvider.removeTxtRecord(dnsRecordName, sha256);
      console.log(
        `[ChallengeResponder] Removed DNS-01 TXT record for ${domain}`
      );
    } catch (err) {
      console.warn(
        `[ChallengeResponder] Failed to remove DNS-01 TXT record: ${err}`
      );
    }
  }

  async registerChallenge(
    challengeType: ChallengeType,
    token: string,
    keyAuthorization: string,
    domain: string,
    ttlSeconds: number = 3600
  ): Promise<void> {
    switch (challengeType) {
      case 'http-01':
        await this.registerHttpChallenge(
          token,
          keyAuthorization,
          domain,
          ttlSeconds
        );
        break;
      case 'dns-01':
        await this.registerDnsChallenge(
          token,
          keyAuthorization,
          domain,
          ttlSeconds
        );
        break;
      default:
        throw new Error(`Unsupported challenge type: ${challengeType}`);
    }
  }

  async unregisterChallenge(
    challengeType: ChallengeType,
    token: string,
    keyAuthorization: string,
    domain: string
  ): Promise<void> {
    switch (challengeType) {
      case 'http-01':
        await this.unregisterHttpChallenge(token);
        break;
      case 'dns-01':
        await this.unregisterDnsChallenge(domain, keyAuthorization);
        break;
      default:
        throw new Error(`Unsupported challenge type: ${challengeType}`);
    }
  }

  getActiveChallengeCount(): number {
    return this.httpTokens.size + this.dnsTokens.size;
  }

  cleanupExpired(): void {
    const now = new Date();

    for (const [token, data] of this.httpTokens) {
      if (now > data.expiresAt) {
        this.httpTokens.delete(token);
      }
    }

    for (const [key, data] of this.dnsTokens) {
      if (now > data.expiresAt) {
        this.dnsTokens.delete(key);
      }
    }
  }

  setDnsProvider(provider: DnsProvider): void {
    this.dnsProvider = provider;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
