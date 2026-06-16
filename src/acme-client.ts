import * as crypto from 'crypto';
import axios, { AxiosInstance, AxiosResponse } from 'axios';
import * as forge from 'node-forge';
import {
  AcmeAccount,
  AcmeAuthorization,
  AcmeChallenge,
  AcmeClientConfig,
  AcmeDirectory,
  AcmeError,
  AcmeIdentifier,
  AcmeKeyPair,
  AcmeOrder,
  ChallengeType,
  CertificateRequest,
  LETSENCRYPT_STAGING_DIRECTORY,
} from './types';

type Jwk = {
  e: string;
  kty: string;
  n: string;
};

export class AcmeClient {
  private config: AcmeClientConfig;
  private directory: AcmeDirectory | null = null;
  private account: AcmeAccount | null = null;
  private nonce: string | null = null;
  private httpClient: AxiosInstance;

  constructor(config: Partial<AcmeClientConfig> & { directoryUrl?: string } = {}) {
    this.config = {
      directoryUrl: LETSENCRYPT_STAGING_DIRECTORY,
      agreeToTerms: true,
      ...config,
    } as AcmeClientConfig;
    this.httpClient = axios.create({
      timeout: 30000,
      headers: {
        'Content-Type': 'application/jose+json',
      },
    });
  }

  async initialize(): Promise<void> {
    this.directory = await this.fetchDirectory();
    await this.getOrCreateAccount();
  }

  private async fetchDirectory(): Promise<AcmeDirectory> {
    const response = await axios.get(this.config.directoryUrl);
    return response.data as AcmeDirectory;
  }

  private async getNonce(): Promise<string> {
    if (this.nonce) {
      const nonce = this.nonce;
      this.nonce = null;
      return nonce;
    }
    const response = await axios.head(this.directory!.newNonce, {
      headers: { 'Replay-Nonce': '' },
    });
    return response.headers['replay-nonce'];
  }

  private storeNonceFromResponse(response: AxiosResponse): void {
    const nonce = response.headers['replay-nonce'];
    if (nonce) {
      this.nonce = nonce;
    }
  }

  generateKeyPair(): AcmeKeyPair {
    const kp = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
      },
    });
    return {
      publicKey: kp.publicKey as unknown as string,
      privateKey: kp.privateKey as unknown as string,
    };
  }

  private jwkFromPublicKey(publicKeyPem: string): Jwk {
    const publicKey = crypto.createPublicKey(publicKeyPem);
    const jwk = publicKey.export({ format: 'jwk' }) as unknown as Jwk;
    return {
      e: jwk.e,
      kty: jwk.kty,
      n: jwk.n,
    };
  }

  private base64urlEncode(data: Buffer | string): string {
    const buffer = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
    return buffer
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  }

  private sha256(data: string): string {
    return this.base64urlEncode(crypto.createHash('sha256').update(data).digest());
  }

  computeKeyAuthorization(token: string): string {
    if (!this.account) {
      throw new Error('Account not initialized');
    }
    const jwk = this.jwkFromPublicKey(this.account.keyPair.publicKey);
    const jwkThumbprint = this.sha256(JSON.stringify({
      e: jwk.e,
      kty: jwk.kty,
      n: jwk.n,
    }));
    return `${token}.${jwkThumbprint}`;
  }

  private async signJws(
    payload: object | string | null,
    url: string,
    kid?: string
  ): Promise<object> {
    if (!this.account) {
      throw new Error('Account not initialized');
    }

    const nonce = await this.getNonce();
    const privateKey = this.account.keyPair.privateKey;

    const jwk = kid ? undefined : this.jwkFromPublicKey(
      this.account.keyPair.publicKey
    );

    const protectedHeader: Record<string, any> = {
      alg: 'RS256',
      nonce,
      url,
    };

    if (kid) {
      protectedHeader.kid = kid;
    } else {
      protectedHeader.jwk = {
        e: jwk!.e,
        kty: jwk!.kty,
        n: jwk!.n,
      };
    }

    const protected64 = this.base64urlEncode(JSON.stringify(protectedHeader));
    const payload64 = payload === null
      ? ''
      : this.base64urlEncode(
          typeof payload === 'string' ? payload : JSON.stringify(payload)
        );

    const signingInput = `${protected64}.${payload64}`;
    const sign = crypto.createSign('RSA-SHA256');
    sign.update(signingInput);
    const signature = this.base64urlEncode(
      sign.sign(privateKey)
    );

    return {
      protected: protected64,
      payload: payload64,
      signature,
    };
  }

  private async signedRequest(
    url: string,
    payload: object | string | null,
    kid?: string
  ): Promise<AxiosResponse> {
    const jws = await this.signJws(payload, url, kid);

    try {
      const response = await this.httpClient.post(url, jws);
      this.storeNonceFromResponse(response);
      return response;
    } catch (error: any) {
      if (error.response) {
        this.storeNonceFromResponse(error.response);
        const acmeError = error.response.data as AcmeError;
        throw new Error(
          `ACME Error [${acmeError.type}]: ${acmeError.detail}${
            acmeError.status ? ` (HTTP ${acmeError.status})` : ''
          }`
        );
      }
      throw error;
    }
  }

  private async getOrCreateAccount(): Promise<AcmeAccount> {
    if (this.account) {
      return this.account;
    }

    const keyPair = this.generateKeyPair();
    this.account = { keyPair };

    const payload: Record<string, any> = {
      termsOfServiceAgreed: this.config.agreeToTerms,
    };

    if (this.config.contact && this.config.contact.length > 0) {
      payload.contact = this.config.contact;
    }

    payload.onlyReturnExisting = false;

    try {
      const response = await this.signedRequest(
        this.directory!.newAccount,
        payload
      );

      this.account.id = response.headers['location'];
      this.account.status = response.data.status;
      this.account.contact = response.data.contact;
    } catch (error) {
      this.account = null;
      throw error;
    }

    return this.account;
  }

  getAccount(): AcmeAccount | null {
    return this.account;
  }

  async createOrder(domains: string[]): Promise<AcmeOrder> {
    const identifiers: AcmeIdentifier[] = domains.map((domain) => ({
      type: 'dns',
      value: domain.replace(/^\*\./, ''),
    }));

    const response = await this.signedRequest(
      this.directory!.newOrder,
      { identifiers },
      this.account!.id
    );

    const order: AcmeOrder = {
      id: response.headers['location'],
      ...response.data,
    };

    return order;
  }

  async getAuthorization(authzUrl: string): Promise<AcmeAuthorization> {
    const response = await this.signedRequest(
      authzUrl,
      '',
      this.account!.id
    );
    return response.data as AcmeAuthorization;
  }

  async getChallenges(
    order: AcmeOrder,
    challengeType: ChallengeType
  ): Promise<Array<{ authorization: AcmeAuthorization; challenge: AcmeChallenge }>> {
    const result = [];

    for (const authzUrl of order.authorizations) {
      const authorization = await this.getAuthorization(authzUrl);
      const challenge = authorization.challenges.find(
        (c) => c.type === challengeType
      );

      if (!challenge) {
        throw new Error(
          `No ${challengeType} challenge found for ${authorization.identifier.value}`
        );
      }

      result.push({ authorization, challenge });
    }

    return result;
  }

  async respondToChallenge(challengeUrl: string): Promise<AcmeChallenge> {
    const response = await this.signedRequest(
      challengeUrl,
      {},
      this.account!.id
    );
    return response.data as AcmeChallenge;
  }

  async pollChallenge(
    challengeUrl: string,
    intervalMs: number = 3000,
    maxAttempts: number = 60
  ): Promise<AcmeChallenge> {
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      const response = await this.signedRequest(
        challengeUrl,
        '',
        this.account!.id
      );
      const challenge = response.data as AcmeChallenge;

      if (challenge.status === 'valid') {
        return challenge;
      }

      if (challenge.status === 'invalid') {
        throw new Error(
          `Challenge failed: ${JSON.stringify(challenge.error)}`
        );
      }

      await this.sleep(intervalMs);
    }

    throw new Error('Challenge validation timed out');
  }

  async pollOrder(
    orderId: string,
    intervalMs: number = 3000,
    maxAttempts: number = 60
  ): Promise<AcmeOrder> {
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      const response = await this.signedRequest(
        orderId,
        '',
        this.account!.id
      );
      const order: AcmeOrder = {
        id: orderId,
        ...response.data,
      };

      if (order.status === 'ready' || order.status === 'valid') {
        return order;
      }

      if (order.status === 'invalid') {
        throw new Error(`Order failed: ${JSON.stringify(order.error)}`);
      }

      await this.sleep(intervalMs);
    }

    throw new Error('Order processing timed out');
  }

  generateCsr(domains: string[]): {
    csrPem: string;
    keyPair: AcmeKeyPair;
  } {
    const keyPair = this.generateKeyPair();
    const privateKey = forge.pki.privateKeyFromPem(keyPair.privateKey);
    const publicKey = forge.pki.publicKeyFromPem(keyPair.publicKey);

    const csr = forge.pki.createCertificationRequest();
    csr.publicKey = publicKey;

    const subjectAttributes = [
      { name: 'commonName', value: domains[0] },
    ];
    csr.setSubject(subjectAttributes);

    const altNames = domains.map((domain) => ({
      type: 2,
      value: domain,
    }));

    csr.setAttributes([
      {
        name: 'extensionRequest',
        extensions: [
          {
            name: 'subjectAltName',
            altNames,
          },
        ],
      },
    ]);

    csr.sign(privateKey, forge.md.sha256.create());

    return {
      csrPem: forge.pki.certificationRequestToPem(csr),
      keyPair,
    };
  }

  private derToBase64Url(der: ArrayBuffer): string {
    const bytes = new Uint8Array(der);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return this.base64urlEncode(Buffer.from(binary, 'binary'));
  }

  private csrToDer(csrPem: string): ArrayBuffer {
    const csrDer = forge.asn1.toDer(
      forge.pki.certificationRequestToAsn1(
        forge.pki.certificationRequestFromPem(csrPem)
      )
    ).getBytes();
    const buffer = new ArrayBuffer(csrDer.length);
    const view = new Uint8Array(buffer);
    for (let i = 0; i < csrDer.length; i++) {
      view[i] = csrDer.charCodeAt(i);
    }
    return buffer;
  }

  async finalizeOrder(
    finalizeUrl: string,
    csrPem: string
  ): Promise<AcmeOrder> {
    const csrDer = this.csrToDer(csrPem);
    const csrBase64 = this.derToBase64Url(csrDer);

    const response = await this.signedRequest(
      finalizeUrl,
      { csr: csrBase64 },
      this.account!.id
    );

    const order: AcmeOrder = {
      id: response.headers['location'],
      ...response.data,
    };

    return order;
  }

  async downloadCertificate(certificateUrl: string): Promise<string> {
    const response = await this.signedRequest(
      certificateUrl,
      '',
      this.account!.id
    );
    return response.data as string;
  }

  async issueCertificate(
    request: CertificateRequest,
    onChallengeReady?: (
      challenge: AcmeChallenge,
      keyAuthorization: string,
      domain: string
    ) => Promise<void>
  ): Promise<{
    certificate: string;
    fullchain: string;
    chain: string;
    privateKey: string;
  }> {
    if (!this.account) {
      throw new Error('ACME client not initialized. Call initialize() first.');
    }

    const order = await this.createOrder(request.domains);

    const challenges = await this.getChallenges(order, request.challengeType);

    for (const { authorization, challenge } of challenges) {
      const keyAuthorization = this.computeKeyAuthorization(challenge.token);
      const domain = authorization.identifier.value;

      if (onChallengeReady) {
        await onChallengeReady(challenge, keyAuthorization, domain);
      }

      await this.respondToChallenge(challenge.url);
    }

    for (const { challenge } of challenges) {
      await this.pollChallenge(challenge.url);
    }

    const readyOrder = await this.pollOrder(order.id!);

    const { csrPem, keyPair } = this.generateCsr(request.domains);

    const finalizedOrder = await this.finalizeOrder(
      readyOrder.finalize,
      csrPem
    );

    const validOrder = finalizedOrder.status === 'valid'
      ? finalizedOrder
      : await this.pollOrder(order.id!);

    if (!validOrder.certificate) {
      throw new Error('Certificate URL not found in order');
    }

    const fullchain = await this.downloadCertificate(validOrder.certificate);

    const { certificate, chain } = this.splitCertificateChain(fullchain);

    return {
      certificate,
      chain,
      fullchain,
      privateKey: keyPair.privateKey,
    };
  }

  private splitCertificateChain(fullchain: string): {
    certificate: string;
    chain: string;
  } {
    const certs = fullchain
      .split(/(?=-----BEGIN CERTIFICATE-----)/g)
      .filter((c) => c.trim().length > 0);

    if (certs.length === 0) {
      throw new Error('No certificates found in chain');
    }

    const certificate = certs[0];
    const chain = certs.slice(1).join('\n');

    return { certificate, chain };
  }

  parseCertificate(certPem: string): {
    serialNumber: string;
    issuedAt: Date;
    expiresAt: Date;
    issuer: string;
    domains: string[];
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

    return {
      serialNumber: cert.serialNumber,
      issuedAt: cert.validity.notBefore,
      expiresAt: cert.validity.notAfter,
      issuer,
      domains: [...new Set(domains)],
    };
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
