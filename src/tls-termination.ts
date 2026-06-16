import * as https from 'https';
import * as http from 'http';
import * as tls from 'tls';
import * as net from 'net';
import * as crypto from 'crypto';
import { CertificateStore } from './certificate-store';
import { TLSTerminationConfig, StoredCertificate, CanaryResult } from './types';
import { ChallengeResponder } from './challenge-responder';

export type RequestHandler = (
  req: http.IncomingMessage,
  res: http.ServerResponse
) => void;

export interface TlsSessionInfo {
  sni: string | undefined;
  protocol: string;
  cipher: string;
  clientCertSubject?: string;
  sessionId?: string;
}

export interface TlsTerminationStats {
  totalTlsHandshakes: number;
  successfulHandshakes: number;
  failedHandshakes: number;
  sniMatches: number;
  sniFallbackCount: number;
  sniMismatchCount: number;
  cachedContextHits: number;
  cachedContextMisses: number;
  httpRequestsForwarded: number;
  httpsRequestsForwarded: number;
  httpRedirects: number;
  challengesServed: number;
  activeConnections: number;
  canaryHits: number;
  canaryMisses: number;
}

export class TLSTermination {
  private config: Required<TLSTerminationConfig>;
  private certStore: CertificateStore;
  private challengeResponder: ChallengeResponder;
  private requestHandler: RequestHandler | null = null;
  private httpsServer: https.Server | null = null;
  private httpServer: http.Server | null = null;
  private defaultContext: tls.SecureContext | null = null;
  private contextCache: Map<string, tls.SecureContext> = new Map();
  private contextCacheTtl: number = 10 * 60 * 1000;
  private contextCacheMeta: Map<string, number> = new Map();
  private defaultDomain: string | null = null;
  private stats: TlsTerminationStats = {
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
  private activeConnections: Set<net.Socket> = new Set();
  private certCacheWatcherInterval: NodeJS.Timeout | null = null;
  private canaryConfig: {
    active: boolean;
    canaryDomains: string[];
    canarySerialNumber: string | null;
    baselineSerialNumber: string | null;
    installedAt: Date | null;
    results: CanaryResult[];
  } = {
    active: false,
    canaryDomains: [],
    canarySerialNumber: null,
    baselineSerialNumber: null,
    installedAt: null,
    results: [],
  };

  constructor(
    certStore: CertificateStore,
    challengeResponder: ChallengeResponder,
    config: Partial<TLSTerminationConfig>
  ) {
    this.certStore = certStore;
    this.challengeResponder = challengeResponder;
    this.config = {
      httpPort: config.httpPort ?? 80,
      httpsPort: config.httpsPort ?? 443,
      defaultDomain: config.defaultDomain ?? '',
      challengePort: config.challengePort ?? 80,
    };
    this.defaultDomain = config.defaultDomain ?? null;
  }

  setRequestHandler(handler: RequestHandler): void {
    this.requestHandler = handler;
  }

  async start(): Promise<void> {
    await this.buildDefaultContext();

    await this.startHttpsServer();

    await this.startUnifiedHttpServer();

    this.startCertCacheWatcher();
  }

  private async startHttpsServer(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      this.httpsServer = https.createServer({
        SNICallback: (servername, cb) => this.sniCallback(servername, cb),
        key: undefined as any,
        cert: undefined as any,
      });

      this.httpsServer.on('tlsClientError', (err, socket) => {
        this.stats.failedHandshakes++;
        this.stats.totalTlsHandshakes++;
        const sni = (socket as any).servername || 'unknown';
        console.warn(
          `[TLSTermination] TLS handshake error for SNI=${sni}: ${err.message}`
        );
      });

      this.httpsServer.on('secureConnection', (socket: tls.TLSSocket) => {
        this.stats.successfulHandshakes++;
        this.stats.totalTlsHandshakes++;
        this.stats.activeConnections++;
        this.activeConnections.add(socket);

        socket.on('close', () => {
          this.stats.activeConnections--;
          this.activeConnections.delete(socket);
        });

        const sessionInfo = this.getSessionInfo(socket);
        if (sessionInfo.sni) {
          console.debug(
            `[TLSTermination] TLS session: SNI=${sessionInfo.sni}, protocol=${sessionInfo.protocol}, cipher=${sessionInfo.cipher}`
          );
        }
      });

      this.httpsServer.on('request', (req, res) => {
        this.stats.httpsRequestsForwarded++;
        this.handleRequest(req, res, true);
      });

      this.httpsServer.on('error', (err: any) => {
        if (err.code === 'EADDRINUSE') {
          console.warn(
            `[TLSTermination] HTTPS port ${this.config.httpsPort} is in use, retrying in 2s...`
          );
          setTimeout(() => {
            this.httpsServer!.listen(this.config.httpsPort);
          }, 2000);
        } else {
          reject(err);
        }
      });

      this.httpsServer.listen(this.config.httpsPort, () => {
        console.log(
          `[TLSTermination] HTTPS server listening on port ${this.config.httpsPort}`
        );
        resolve();
      });
    });
  }

  private async startUnifiedHttpServer(): Promise<void> {
    return new Promise<void>((resolve) => {
      this.httpServer = http.createServer((req, res) => {
        const url = req.url || '/';

        if (this.challengeResponder.isChallengePath(url)) {
          const result = this.challengeResponder.handleHttpChallengeRequest(url);
          if (result.found && result.keyAuthorization) {
            this.stats.challengesServed++;
            res.statusCode = 200;
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            res.setHeader('Cache-Control', 'no-store');
            res.end(result.keyAuthorization);
            return;
          }

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

        const host = req.headers['host'] || this.defaultDomain || 'localhost';
        const targetHost = (host as string).replace(/:\d+$/, '');
        const targetPort =
          this.config.httpsPort === 443 ? '' : `:${this.config.httpsPort}`;
        const redirectUrl = `https://${targetHost}${targetPort}${req.url}`;

        this.stats.httpRedirects++;

        res.writeHead(301, {
          Location: redirectUrl,
          'Cache-Control': 'max-age=3600',
          'Strict-Transport-Security':
            'max-age=31536000; includeSubDomains; preload',
        });
        res.end('Moved Permanently');
      });

      this.httpServer.on('error', (err: any) => {
        if (err.code === 'EADDRINUSE') {
          console.warn(
            `[TLSTermination] HTTP port ${this.config.httpPort} is in use, retrying in 2s...`
          );
          setTimeout(() => {
            this.httpServer!.listen(this.config.httpPort);
          }, 2000);
        } else {
          console.error(
            `[TLSTermination] HTTP server error: ${err.message}`
          );
        }
      });

      this.httpServer.listen(this.config.httpPort, () => {
        console.log(
          `[TLSTermination] HTTP server (challenges + redirect) listening on port ${this.config.httpPort}`
        );
        resolve();
      });
    });
  }

  private async buildDefaultContext(): Promise<void> {
    if (this.defaultDomain) {
      const tlsContext = await this.certStore.getTlsContextForDomain(
        this.defaultDomain
      );
      if (tlsContext) {
        this.defaultContext = tls.createSecureContext({
          key: tlsContext.key,
          cert: tlsContext.cert,
          ca: tlsContext.ca,
          minVersion: 'TLSv1.2',
          ciphers: this.getRecommendedCiphers(),
          honorCipherOrder: true,
        });
        console.log(
          `[TLSTermination] Default TLS context built for domain: ${this.defaultDomain}`
        );
        return;
      }
    }

    const managedDomains = this.certStore.getManagedDomains();
    if (managedDomains.length > 0) {
      const tlsContext = await this.certStore.getTlsContextForDomain(
        managedDomains[0]
      );
      if (tlsContext) {
        this.defaultContext = tls.createSecureContext({
          key: tlsContext.key,
          cert: tlsContext.cert,
          ca: tlsContext.ca,
          minVersion: 'TLSv1.2',
          ciphers: this.getRecommendedCiphers(),
          honorCipherOrder: true,
        });
        this.defaultDomain = managedDomains[0];
        console.log(
          `[TLSTermination] Default TLS context fallback to: ${managedDomains[0]}`
        );
        return;
      }
    }

    console.warn(
      '[TLSTermination] No certificates available for default TLS context. Generating self-signed fallback.'
    );
    this.defaultContext = this.createSelfSignedContext('localhost');
  }

  private createSelfSignedContext(domain: string): tls.SecureContext {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    const forge = require('node-forge');
    const pk = forge.pki.privateKeyFromPem(privateKey);
    const cert = forge.pki.createCertificate();

    cert.publicKey = forge.pki.publicKeyFromPem(publicKey);
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(
      cert.validity.notBefore.getFullYear() + 1
    );

    const attrs = [
      { name: 'commonName', value: domain },
      { name: 'countryName', value: 'US' },
      { name: 'organizationName', value: 'Fallback' },
    ];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.setExtensions([
      { name: 'basicConstraints', cA: true },
      {
        name: 'subjectAltName',
        altNames: [
          { type: 2, value: domain },
          { type: 2, value: 'localhost' },
          { type: 7, ip: '127.0.0.1' },
        ],
      },
    ]);
    cert.sign(pk, forge.md.sha256.create());

    const certPem = forge.pki.certificateToPem(cert);

    return tls.createSecureContext({
      key: privateKey,
      cert: certPem,
      minVersion: 'TLSv1.2',
      ciphers: this.getRecommendedCiphers(),
    });
  }

  private getRecommendedCiphers(): string {
    return [
      'ECDHE-ECDSA-AES256-GCM-SHA384',
      'ECDHE-RSA-AES256-GCM-SHA384',
      'ECDHE-ECDSA-CHACHA20-POLY1305',
      'ECDHE-RSA-CHACHA20-POLY1305',
      'ECDHE-ECDSA-AES128-GCM-SHA256',
      'ECDHE-RSA-AES128-GCM-SHA256',
    ].join(':');
  }

  private isCanaryDomain(domain: string): boolean {
    if (!this.canaryConfig.active) {
      return false;
    }
    const normalized = domain.toLowerCase();
    for (const canary of this.canaryConfig.canaryDomains) {
      const c = canary.toLowerCase();
      if (c === normalized) {
        return true;
      }
      if (c.startsWith('*.')) {
        const suffix = c.slice(1);
        if (normalized.endsWith(suffix) && normalized.length > suffix.length) {
          return true;
        }
      }
    }
    return false;
  }

  private async getDefaultContext(): Promise<tls.SecureContext> {
    if (this.defaultDomain) {
      const tlsCtx = await this.certStore.getTlsContextForDomain(
        this.defaultDomain
      );
      if (tlsCtx) {
        return tls.createSecureContext({
          key: tlsCtx.key,
          cert: tlsCtx.cert,
          ca: tlsCtx.ca,
          minVersion: 'TLSv1.2',
          ciphers: this.getRecommendedCiphers(),
          honorCipherOrder: true,
        });
      }
    }

    if (!this.defaultContext) {
      this.defaultContext = this.createSelfSignedContext('localhost');
    }
    return this.defaultContext!;
  }

  private async sniCallback(
    servername: string,
    cb: (err: Error | null, ctx?: tls.SecureContext) => void
  ): Promise<void> {
    try {
      const normalizedServername = servername.toLowerCase();

      const cached = this.getContextFromCache(normalizedServername);
      if (cached) {
        this.stats.cachedContextHits++;
        cb(null, cached);
        return;
      }

      this.stats.cachedContextMisses++;

      let targetSerial: string | null = null;
      if (this.isCanaryDomain(normalizedServername)) {
        targetSerial = this.canaryConfig.canarySerialNumber;
        this.stats.canaryHits++;
      } else {
        this.stats.canaryMisses++;
      }

      let tlsContext: { cert: string; key: string; ca?: string } | null = null;

      if (targetSerial) {
        tlsContext = await this.certStore.getTlsContextForSerial(targetSerial);
      }

      if (!tlsContext) {
        tlsContext = await this.certStore.getTlsContextForDomain(
          normalizedServername
        );
      }

      if (!tlsContext) {
        tlsContext = await this.findWildcardMatch(normalizedServername);
      }

      if (tlsContext) {
        this.stats.sniMatches++;
        const secureContext = tls.createSecureContext({
          key: tlsContext.key,
          cert: tlsContext.cert,
          ca: tlsContext.ca,
          minVersion: 'TLSv1.2',
          ciphers: this.getRecommendedCiphers(),
          honorCipherOrder: true,
        });

        this.putContextInCache(normalizedServername, secureContext);
        cb(null, secureContext);
      } else {
        this.stats.sniFallbackCount++;
        console.warn(
          `[TLSTermination] No certificate found for SNI=${servername}, using default`
        );
        const defaultCtx = await this.getDefaultContext();
        cb(null, defaultCtx);
      }
    } catch (err) {
      this.stats.sniMismatchCount++;
      console.error(
        `[TLSTermination] SNI callback error for ${servername}: ${(err as Error).message}`
      );
      const defaultCtx = await this.getDefaultContext();
      cb(null, defaultCtx);
    }
  }

  private async findWildcardMatch(
    domain: string
  ): Promise<{ cert: string; key: string; ca?: string } | null> {
    const parts = domain.split('.');
    if (parts.length < 2) {
      return null;
    }

    const wildcardDomain = `*.${parts.slice(1).join('.')}`;
    return this.certStore.getTlsContextForDomain(wildcardDomain);
  }

  private getContextFromCache(servername: string): tls.SecureContext | null {
    const now = Date.now();
    const cachedAt = this.contextCacheMeta.get(servername);

    if (!cachedAt) {
      return null;
    }

    if (now - cachedAt > this.contextCacheTtl) {
      this.contextCache.delete(servername);
      this.contextCacheMeta.delete(servername);
      return null;
    }

    return this.contextCache.get(servername) || null;
  }

  private putContextInCache(
    servername: string,
    context: tls.SecureContext
  ): void {
    this.contextCache.set(servername, context);
    this.contextCacheMeta.set(servername, Date.now());
  }

  invalidateContextCache(domain?: string): void {
    if (domain) {
      const normalized = domain.toLowerCase();
      this.contextCache.delete(normalized);
      this.contextCacheMeta.delete(normalized);

      if (normalized.startsWith('*.')) {
        const suffix = normalized.slice(1);
        const keysToDelete: string[] = [];
        for (const cachedKey of this.contextCache.keys()) {
          if (cachedKey.endsWith(suffix)) {
            keysToDelete.push(cachedKey);
          }
        }
        for (const k of keysToDelete) {
          this.contextCache.delete(k);
          this.contextCacheMeta.delete(k);
        }
      }

      const parts = normalized.split('.');
      if (parts.length >= 2) {
        const wildcardKey = `*.${parts.slice(1).join('.')}`;
        this.contextCache.delete(wildcardKey);
        this.contextCacheMeta.delete(wildcardKey);
      }

      console.log(
        `[TLSTermination] Invalidated TLS context cache for ${domain} (including wildcard variants)`
      );
    } else {
      this.contextCache.clear();
      this.contextCacheMeta.clear();
      this.buildDefaultContext().catch((err) => {
        console.error(
          `[TLSTermination] Failed to rebuild default context: ${err.message}`
        );
      });
      console.log('[TLSTermination] Invalidated entire TLS context cache');
    }
  }

  invalidateContextCacheForDomains(domains: string[]): number {
    let invalidated = 0;
    for (const domain of domains) {
      const before = this.contextCache.size;
      this.invalidateContextCache(domain);
      invalidated += before - this.contextCache.size;
    }
    return invalidated;
  }

  getCachedDomains(): string[] {
    return Array.from(this.contextCache.keys());
  }

  private startCertCacheWatcher(): void {
    this.certCacheWatcherInterval = setInterval(() => {
      this.invalidateContextCache();
    }, 60 * 60 * 1000);
  }

  private handleRequest(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    isHttps: boolean
  ): void {
    if (isHttps) {
      (req as any).isSecure = true;
      const socket = req.socket as tls.TLSSocket;
      const sessionInfo = this.getSessionInfo(socket);
      (req as any).tlsSession = sessionInfo;
    } else {
      (req as any).isSecure = false;
    }

    if (this.requestHandler) {
      try {
        this.requestHandler(req, res);
      } catch (err) {
        console.error(
          `[TLSTermination] Request handler error: ${(err as Error).message}`
        );
        if (!res.headersSent) {
          res.statusCode = 500;
          res.setHeader('Content-Type', 'application/json');
          res.end(
            JSON.stringify({ error: 'Internal Server Error', code: 500 })
          );
        }
      }
    } else {
      res.statusCode = 502;
      res.setHeader('Content-Type', 'application/json');
      res.end(
        JSON.stringify({
          error: 'No upstream handler configured',
          code: 502,
        })
      );
    }
  }

  private getSessionInfo(socket: tls.TLSSocket): TlsSessionInfo {
    const cipher = socket.getCipher();
    const protocol = socket.getProtocol?.() || 'TLS';
    const session = socket.getSession?.();
    const peerCert = socket.getPeerCertificate?.(true);

    const servername = socket.servername;
    const sniVal: string | undefined = typeof servername === 'string'
      ? servername
      : undefined;

    let clientCertSubject: string | undefined;
    const cnField = peerCert?.subject?.CN;
    if (Array.isArray(cnField)) {
      clientCertSubject = cnField[0];
    } else if (typeof cnField === 'string') {
      clientCertSubject = cnField;
    }

    return {
      sni: sniVal,
      protocol,
      cipher: cipher ? cipher.name : 'unknown',
      clientCertSubject,
      sessionId: session
        ? session.slice(0, 32).toString('hex')
        : undefined,
    };
  }

  async stop(): Promise<void> {
    if (this.certCacheWatcherInterval) {
      clearInterval(this.certCacheWatcherInterval);
      this.certCacheWatcherInterval = null;
    }

    if (this.httpsServer) {
      await new Promise<void>((resolve) => {
        this.httpsServer!.close(() => {
          console.log('[TLSTermination] HTTPS server stopped');
          resolve();
        });
      });
      this.httpsServer = null;
    }

    if (this.httpServer) {
      await new Promise<void>((resolve) => {
        this.httpServer!.close(() => {
          console.log('[TLSTermination] HTTP server stopped');
          resolve();
        });
      });
      this.httpServer = null;
    }

    for (const socket of this.activeConnections) {
      socket.destroy();
    }
    this.activeConnections.clear();
  }

  getStats(): TlsTerminationStats {
    return { ...this.stats, activeConnections: this.activeConnections.size };
  }

  async getCertificatesStatus(): Promise<
    Array<{
      domain: string;
      serialNumber: string;
      expiresAt: Date;
      daysUntilExpiry: number;
      hasContext: boolean;
    }>
  > {
    const certs = await this.certStore.getAllCertificates();
    const now = new Date();

    return certs.map((cert: StoredCertificate) => {
      const daysUntilExpiry = Math.ceil(
        (cert.expiresAt.getTime() - now.getTime()) / (24 * 60 * 60 * 1000)
      );
      return {
        domain: cert.domain,
        serialNumber: cert.serialNumber,
        expiresAt: cert.expiresAt,
        daysUntilExpiry,
        hasContext: this.contextCache.has(cert.domain.toLowerCase()),
      };
    });
  }

  setDefaultDomain(domain: string): void {
    this.defaultDomain = domain;
    this.buildDefaultContext().catch((err) => {
      console.error(
        `[TLSTermination] Failed to set default domain ${domain}: ${err.message}`
      );
    });
  }

  getDefaultDomain(): string | null {
    return this.defaultDomain;
  }

  getConfig(): { httpPort: number; httpsPort: number } {
    return {
      httpPort: this.config.httpPort,
      httpsPort: this.config.httpsPort,
    };
  }

  setCanaryConfig(config: {
    canaryDomains: string[];
    canarySerialNumber: string;
    baselineSerialNumber: string;
  }): void {
    this.canaryConfig = {
      active: true,
      canaryDomains: config.canaryDomains,
      canarySerialNumber: config.canarySerialNumber,
      baselineSerialNumber: config.baselineSerialNumber,
      installedAt: new Date(),
      results: [],
    };

    this.invalidateContextCacheForDomains(config.canaryDomains);

    console.log(
      `[TLSTermination] Canary deployment activated: ${config.canaryDomains.length} domain(s) -> serial ${config.canarySerialNumber}`
    );
  }

  getCanaryStatus(): {
    active: boolean;
    canaryDomains: string[];
    canarySerialNumber: string | null;
    baselineSerialNumber: string | null;
    canaryInstalledAt: Date | null;
    results: CanaryResult[];
    successCount: number;
    failureCount: number;
    readyToPromote: boolean;
    readyToRollback: boolean;
  } {
    const successCount = this.canaryConfig.results.filter(
      (r) => r.success
    ).length;
    const failureCount = this.canaryConfig.results.filter(
      (r) => !r.success
    ).length;
    const totalProbes = successCount + failureCount;
    const readyToPromote =
      this.canaryConfig.active &&
      totalProbes >= 3 &&
      failureCount === 0;
    const readyToRollback =
      this.canaryConfig.active && failureCount > 0;

    return {
      active: this.canaryConfig.active,
      canaryDomains: [...this.canaryConfig.canaryDomains],
      canarySerialNumber: this.canaryConfig.canarySerialNumber,
      baselineSerialNumber: this.canaryConfig.baselineSerialNumber,
      canaryInstalledAt: this.canaryConfig.installedAt,
      results: [...this.canaryConfig.results],
      successCount,
      failureCount,
      readyToPromote,
      readyToRollback,
    };
  }

  async probeCanary(domain: string): Promise<CanaryResult> {
    const host = this.config.httpsPort === 443 ? domain : `${domain}:${this.config.httpsPort}`;

    try {
      const result = await new Promise<CanaryResult>((resolve, reject) => {
        const socket = tls.connect(
          {
            host: domain,
            port: this.config.httpsPort,
            servername: domain,
            rejectUnauthorized: false,
            timeout: 5000,
          },
          () => {
            const peerCert = socket.getPeerCertificate();
            const subject = peerCert.subject as Record<string, string>;
            const issuer = peerCert.issuer as Record<string, string>;
            const result: CanaryResult = {
              domain,
              serialNumber: this.canaryConfig.canarySerialNumber || '',
              timestamp: new Date(),
              success: true,
              tlsVersion: socket.getProtocol() || undefined,
              cipher: socket.getCipher()?.name,
              peerCertSerial: peerCert.serialNumber,
              peerCertSubject: subject,
              peerCertIssuer: issuer,
              peerCertSubjectCN: subject.CN,
              peerCertIssuerCN: issuer.CN,
              peerCertValidFrom: peerCert.valid_from
                ? new Date(peerCert.valid_from)
                : undefined,
              peerCertValidTo: peerCert.valid_to
                ? new Date(peerCert.valid_to)
                : undefined,
            };
            socket.end();
            resolve(result);
          }
        );

        socket.on('error', (err) => {
          const result: CanaryResult = {
            domain,
            serialNumber: this.canaryConfig.canarySerialNumber || '',
            timestamp: new Date(),
            success: false,
            error: err.message,
          };
          reject(result);
        });

        socket.on('timeout', () => {
          socket.destroy();
          const result: CanaryResult = {
            domain,
            serialNumber: this.canaryConfig.canarySerialNumber || '',
            timestamp: new Date(),
            success: false,
            error: 'Connection timeout',
          };
          reject(result);
        });
      });

      if (this.canaryConfig.active) {
        this.canaryConfig.results.push(result);
        if (this.canaryConfig.results.length > 50) {
          this.canaryConfig.results = this.canaryConfig.results.slice(-50);
        }
      }

      return result;
    } catch (result) {
      if (this.canaryConfig.active) {
        this.canaryConfig.results.push(result as CanaryResult);
        if (this.canaryConfig.results.length > 50) {
          this.canaryConfig.results = this.canaryConfig.results.slice(-50);
        }
      }
      return result as CanaryResult;
    }
  }

  promoteCanary(): void {
    if (!this.canaryConfig.active) {
      throw new Error('No canary deployment active');
    }

    const canaryDomains = [...this.canaryConfig.canaryDomains];
    this.canaryConfig = {
      active: false,
      canaryDomains: [],
      canarySerialNumber: null,
      baselineSerialNumber: null,
      installedAt: null,
      results: [],
    };

    this.invalidateContextCache();

    console.log(
      `[TLSTermination] Canary promoted: ${canaryDomains.length} domain(s)`
    );
  }

  rollbackCanary(): void {
    if (!this.canaryConfig.active) {
      throw new Error('No canary deployment active');
    }

    const canaryDomains = [...this.canaryConfig.canaryDomains];
    const canarySerial = this.canaryConfig.canarySerialNumber;
    this.canaryConfig = {
      active: false,
      canaryDomains: [],
      canarySerialNumber: null,
      baselineSerialNumber: null,
      installedAt: null,
      results: [],
    };

    this.invalidateContextCacheForDomains(canaryDomains);

    console.log(
      `[TLSTermination] Canary rolled back: ${canaryDomains.length} domain(s), serial ${canarySerial}`
    );
  }

  async getDefaultCertificateSerial(): Promise<string | null> {
    if (!this.defaultDomain) {
      return null;
    }
    const cert = await this.certStore.getCertificateByDomain(
      this.defaultDomain
    );
    return cert?.serialNumber || null;
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
    const domain = this.defaultDomain;
    const expectedSerial = await this.getDefaultCertificateSerial();

    if (!domain) {
      return {
        success: false,
        domain: null,
        expectedSerial: null,
        error: 'No default domain configured',
      };
    }

    try {
      return await new Promise((resolve) => {
        const socket = tls.connect(
          {
            host: domain,
            port: this.config.httpsPort,
            servername: domain,
            rejectUnauthorized: false,
            timeout: 5000,
          },
          () => {
            const peerCert = socket.getPeerCertificate();
            const subject = peerCert.subject as Record<string, string>;
            const issuer = peerCert.issuer as Record<string, string>;
            const result = {
              success: true,
              domain,
              expectedSerial,
              actualSerial: peerCert.serialNumber,
              actualSubject: subject.CN || JSON.stringify(subject),
              actualIssuer: issuer.CN || JSON.stringify(issuer),
              validTo: peerCert.valid_to
                ? new Date(peerCert.valid_to)
                : undefined,
            };
            socket.end();
            resolve(result);
          }
        );

        socket.on('error', (err) => {
          resolve({
            success: false,
            domain,
            expectedSerial,
            error: err.message,
          });
        });

        socket.on('timeout', () => {
          socket.destroy();
          resolve({
            success: false,
            domain,
            expectedSerial,
            error: 'Connection timeout',
          });
        });
      });
    } catch (err) {
      return {
        success: false,
        domain,
        expectedSerial,
        error: (err as Error).message,
      };
    }
  }
}
