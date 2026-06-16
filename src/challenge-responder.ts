import * as http from 'http';
import * as crypto from 'crypto';
import { ChallengeToken, ChallengeType, DnsProvider } from './types';

export class ChallengeResponder {
  private httpServer: http.Server | null = null;
  private httpTokens: Map<string, ChallengeToken> = new Map();
  private port: number;
  private dnsTokens: Map<string, ChallengeToken> = new Map();
  private dnsProvider: DnsProvider | null = null;

  constructor(port: number = 80, dnsProvider?: DnsProvider) {
    this.port = port;
    this.dnsProvider = dnsProvider || null;
  }

  async start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.httpServer = http.createServer((req, res) => {
        this.handleHttpRequest(req, res);
      });

      this.httpServer.on('error', (err: any) => {
        if (err.code === 'EADDRINUSE') {
          console.warn(
            `[ChallengeResponder] Port ${this.port} is in use, attempting coexistence with existing server`
          );
          resolve();
        } else {
          reject(err);
        }
      });

      this.httpServer.listen(this.port, () => {
        console.log(
          `[ChallengeResponder] HTTP challenge server started on port ${this.port}`
        );
        resolve();
      });
    });
  }

  async stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.httpServer) {
        this.httpServer.close(() => {
          this.httpServer = null;
          console.log('[ChallengeResponder] HTTP challenge server stopped');
          resolve();
        });
      } else {
        resolve();
      }
    });
  }

  private handleHttpRequest(
    req: http.IncomingMessage,
    res: http.ServerResponse
  ): void {
    const url = req.url || '/';

    if (!url.startsWith('/.well-known/acme-challenge/')) {
      res.statusCode = 404;
      res.setHeader('Content-Type', 'application/problem+json');
      res.end(
        JSON.stringify({
          type: 'urn:ietf:params:acme:error:malformed',
          detail: 'Not a valid ACME challenge path',
          status: 404,
        })
      );
      return;
    }

    const token = url.substring('/.well-known/acme-challenge/'.length);

    const stored = this.httpTokens.get(token);

    if (!stored) {
      res.statusCode = 404;
      res.setHeader('Content-Type', 'application/problem+json');
      res.end(
        JSON.stringify({
          type: 'urn:ietf:params:acme:error:malformed',
          detail: 'Challenge token not found',
          status: 404,
        })
      );
      return;
    }

    if (new Date() > stored.expiresAt) {
      this.httpTokens.delete(token);
      res.statusCode = 404;
      res.setHeader('Content-Type', 'application/problem+json');
      res.end(
        JSON.stringify({
          type: 'urn:ietf:params:acme:error:malformed',
          detail: 'Challenge token has expired',
          status: 404,
        })
      );
      return;
    }

    res.statusCode = 200;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.end(stored.keyAuthorization);

    console.log(
      `[ChallengeResponder] HTTP-01 challenge served for ${stored.domain}: ${token}`
    );
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
      } catch (err) {
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

  getPort(): number {
    return this.port;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
