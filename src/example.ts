import { AcmeTlsManager, DnsProvider } from './index';

class MockDnsProvider implements DnsProvider {
  name = 'mock';
  private records: Map<string, string[]> = new Map();

  async addTxtRecord(domain: string, value: string): Promise<void> {
    console.log(`[MockDNS] Add TXT: ${domain} = "${value}"`);
    if (!this.records.has(domain)) {
      this.records.set(domain, []);
    }
    this.records.get(domain)!.push(value);
  }

  async removeTxtRecord(domain: string, value: string): Promise<void> {
    console.log(`[MockDNS] Remove TXT: ${domain} = "${value}"`);
    const records = this.records.get(domain);
    if (records) {
      const idx = records.indexOf(value);
      if (idx > -1) {
        records.splice(idx, 1);
      }
    }
  }
}

async function exampleUsage() {
  console.log('========================================');
  console.log('  ACME TLS Manager - Usage Example');
  console.log('========================================\n');

  const dnsProvider = new MockDnsProvider();

  const manager = new AcmeTlsManager({
    storageDir: './example-data',
    useProduction: false,
    challenge: {
      port: 8080,
      dnsProvider,
    },
    tls: {
      httpPort: 8080,
      httpsPort: 8443,
    },
    renewal: {
      renewBeforeDays: 30,
      checkIntervalMs: 60 * 60 * 1000,
    },
    storage: {
      encryptPrivateKeys: false,
    },
  });

  console.log('[1/5] Manager Configuration:');
  console.log('  - Storage directory: ./example-data');
  console.log('  - ACME: Let\'s Encrypt Staging (for demo)');
  console.log('  - Challenge port: 8080 (HTTP-01)');
  console.log('  - HTTPS port: 8443, HTTP port: 8080');
  console.log('  - Renewal: 30 days before expiry, hourly check');
  console.log('');

  console.log('[2/5] Setting up request handler...');
  console.log('  - HTTPS handler echoes request info + TLS session data');
  console.log('  - HTTP requests (non-challenge) redirect to HTTPS');
  console.log('');

  console.log('[3/5] Storage Module (not initialized online mode):');
  console.log('  - Would persist certificates to ./example-data/certs/<serial>/');
  console.log('  - Files per certificate: cert.pem, chain.pem, fullchain.pem, privkey.pem');
  console.log('  - Domain index maintained in index.json');
  console.log('  - Optional AES-256-GCM encryption for private keys via PBKDF2');
  console.log('');

  console.log('========================================');
  console.log('  Module Architecture & Workflow Guide');
  console.log('========================================\n');

  console.log('【1. ACME 账户密钥与 CA 交互】');
  console.log('   • AcmeClient 使用 RSA-2048 密钥对与 ACME CA 通信');
  console.log('   • 所有请求通过 JWS (JSON Web Signature) 签名，采用 RS256 算法');
  console.log('   • 账户创建时注册 contact 邮箱并同意 ToS');
  console.log('   • 使用 Replay-Nonce 防止重放攻击');
  console.log('   • 后续请求使用 kid（账户URL）替代 jwk\n');

  console.log('【2. 证书订单流程】');
  console.log('   ① 调用 newOrder，提交 identifiers（域名列表）');
  console.log('   ② CA 返回 order 对象，包含 authorizations 列表');
  console.log('   ③ 对每个 authorization，选择挑战类型（HTTP-01/DNS-01）');
  console.log('   ④ 完成挑战后，CA 将 authorization 状态置为 valid');
  console.log('   ⑤ 所有授权就绪后，调用 finalize URL，提交 CSR');
  console.log('   ⑥ 轮询 order 状态，valid 后从 certificate URL 下载\n');

  console.log('【3. 域名所有权验证】');
  console.log('   HTTP-01:');
  console.log('     • 计算 keyAuthorization = token + "." + jwk_thumbprint');
  console.log('     • ChallengeResponder 在端口 80 提供 /.well-known/acme-challenge/<token>');
  console.log('     • CA 访问该路径验证内容是否匹配');
  console.log('   DNS-01:');
  console.log('     • 计算 dnsValue = base64url(sha256(keyAuthorization))');
  console.log('     • 在 _acme-challenge.<domain> 添加 TXT 记录');
  console.log('     • CA 查询 DNS TXT 记录验证匹配\n');

  console.log('【4. 证书与私钥安全存储】');
  console.log('   • CertificateStore 将数据持久化到 storageDir/certs/<serial>/');
  console.log('   • 文件: cert.pem, chain.pem, fullchain.pem, privkey.pem');
  console.log('   • 可选 AES-256-GCM 加密私钥（通过 PBKDF2 派生密钥）');
  console.log('   • 文件权限 0600，目录 0700');
  console.log('   • 通过 index.json 维护 domain→serial 索引\n');

  console.log('【5. 自动续期机制】');
  console.log('   • RenewalScheduler 按 checkIntervalMs 周期性检查');
  console.log('   • 证书到期前 renewBeforeDays 天触发续期（默认30天）');
  console.log('   • 失败重试采用指数退避策略（最多 maxRetries 次）');
  console.log('   • 续期成功后自动替换旧证书并刷新 TLS 上下文缓存\n');

  console.log('【6. SNI 证书选择】');
  console.log('   • TLSTermination 通过 SNICallback 接收客户端 ClientHello 中的 server_name');
  console.log('   • 精确匹配域名 → 查找对应证书');
  console.log('   • 通配符匹配（如 *.example.com 匹配 sub.example.com）');
  console.log('   • 无匹配时使用 defaultDomain 的证书');
  console.log('   • 启用 TLS 上下文缓存减少文件读取');
  console.log('   • 最小协议版本 TLSv1.2，现代加密套件优先\n');

  console.log('【7. 挑战与正常流量共存】');
  console.log('   • HTTP 服务器在同一端口区分路径:');
  console.log('     - /\.well-known/acme-challenge/* → ChallengeResponder 处理');
  console.log('     - 其他路径 → 301 重定向到 HTTPS');
  console.log('   • HTTPS 端口正常处理业务流量');
  console.log('   • 端口 80 同时承担 HTTP-01 验证和重定向功能\n');

  console.log('========================================');
  console.log('  Example: Manual Certificate Request');
  console.log('========================================\n');
  console.log('Note: Actual issuance requires:');
  console.log('  1. Publicly accessible domain');
  console.log('  2. Port 80 open (HTTP-01) or DNS control (DNS-01)');
  console.log('  3. Use production directory URL for real certs');
  console.log('');
  console.log('Usage:');
  console.log('  await manager.requestCertificate({');
  console.log('    domains: ["example.com", "www.example.com"],');
  console.log('    challengeType: "http-01",');
  console.log('  });\n');

  console.log('[Cleanup] This is a demo - not starting servers in example mode.');
  console.log('In production, call: await manager.start(handler)');
  console.log('');
  console.log('✓ Demo complete');
}

exampleUsage().catch((err) => {
  console.error('Example failed:', err);
  process.exit(1);
});
