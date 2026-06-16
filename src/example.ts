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
      dnsProvider,
    },
    tls: {
      httpPort: 8080,
      httpsPort: 8443,
    },
    renewal: {
      renewBeforeDays: 30,
      checkIntervalMs: 60 * 60 * 1000,
      retryDelayMs: 5 * 60 * 1000,
      maxRetries: 10,
    },
    storage: {
      encryptPrivateKeys: false,
    },
    domains: [
      {
        domains: ['example.com', 'www.example.com'],
        challengeType: 'http-01',
      },
      {
        domains: ['*.app.example.com', 'app.example.com'],
        challengeType: 'dns-01',
      },
    ],
  });

  console.log('[1/6] Manager Configuration:');
  console.log('  - Storage directory: ./example-data');
  console.log('  - ACME: Let\'s Encrypt Staging (for demo)');
  console.log('  - HTTPS port: 8443, HTTP port: 8080');
  console.log('  - Renewal: 30 days before expiry, hourly check');
  console.log('  - Managed domain groups:');
  console.log('    • example.com (HTTP-01) + www.example.com');
  console.log('    • *.app.example.com (DNS-01, wildcard enforced) + app.example.com');
  console.log('');

  console.log('[2/6] Wildcard Domain Challenge Enforcement:');
  console.log('  ✓ Any domain group containing *. wildcard will FORCE DNS-01');
  console.log('  ✓ Even if you specify http-01 in config, it will be overridden to dns-01');
  console.log('  ✓ Regular domains can still use HTTP-01 independently');
  console.log('  ✓ Each domain group maintains its own challenge type, no cross-contamination');
  console.log('');

  console.log('[3/6] Status Monitoring API (getManagedStatus):');
  console.log('  Provides comprehensive service status including:');
  console.log('  • All managed certificates with expiry countdown');
  console.log('  • Renewal task status, failure history, next retry time');
  console.log('  • TLS handshake stats, active connections');
  console.log('  • Per-domain configuration and auto-renewal status');
  console.log('  • Private key encryption status per certificate');
  console.log('');

  console.log('[4/6] Persistent Renewal Tasks:');
  console.log('  ✓ Renewal tasks saved to renewal-tasks.json');
  console.log('  ✓ Failure history (last 10 errors) persisted across restarts');
  console.log('  ✓ Next retry time saved - restarts resume from same schedule');
  console.log('  ✓ Exponential backoff: retryDelay * 2^(attempt-1)');
  console.log('  ✓ In-flight tasks marked failed after restart');
  console.log('');

  console.log('[5/6] Smooth Certificate Rotation:');
  console.log('  ✓ New certificate SAVED FIRST before old one is removed');
  console.log('  ✓ TLS context cache invalidated immediately after save');
  console.log('  ✓ Old certificate only removed after new one is active');
  console.log('  ✓ If renewal fails, old certificate remains untouched');
  console.log('  ✓ Default domain auto-updated if it was using the old cert');
  console.log('');

  console.log('[6/6] Challenge Cleanup Guarantees:');
  console.log('  ✓ HTTP tokens cleaned on BOTH success AND failure');
  console.log('  ✓ DNS TXT records removed on BOTH success AND failure');
  console.log('  ✓ Partial failures (e.g., one domain fails in SAN) still cleanup');
  console.log('  ✓ Each cleanup operation wrapped in try/catch to not mask original error');
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
  console.log('   • 文件: cert.pem, chain.pem, fullchain.pem, privkey.pem, cert.json');
  console.log('   • 可选 AES-256-GCM 加密私钥（通过 PBKDF2 派生密钥，salt 随密文存储）');
  console.log('   • 文件权限 0600，目录 0700');
  console.log('   • 通过 index.json 维护 domain→serial 索引');
  console.log('   • cert.json 包含 challengeType，确保续期时沿用相同验证方式\n');

  console.log('【5. 自动续期机制】');
  console.log('   • RenewalScheduler 按 checkIntervalMs 周期性检查');
  console.log('   • 证书到期前 renewBeforeDays 天触发续期（默认30天）');
  console.log('   • 每证书独立任务，从 cert.json 读取 challengeType');
  console.log('   • 通配符域名强制 DNS-01，不受全局或历史配置影响');
  console.log('   • 失败重试采用指数退避策略（最多 maxRetries 次）');
  console.log('   • 任务状态持久化到 renewal-tasks.json，重启后恢复重试节奏\n');

  console.log('【6. SNI 证书选择】');
  console.log('   • TLSTermination 通过 SNICallback 接收客户端 ClientHello 中的 server_name');
  console.log('   • 精确匹配域名 → 查找对应证书');
  console.log('   • 通配符匹配（如 *.example.com 匹配 sub.example.com）');
  console.log('   • 无匹配时使用 defaultDomain 的证书');
  console.log('   • 启用 TLS 上下文缓存减少文件读取');
  console.log('   • 最小协议版本 TLSv1.2，现代加密套件优先\n');

  console.log('【7. 挑战与正常流量共存】');
  console.log('   • HTTP 服务器在同一端口区分路径:');
  console.log('     - /.well-known/acme-challenge/* → ChallengeResponder 处理');
  console.log('     - 其他路径 → 301 重定向到 HTTPS');
  console.log('   • HTTPS 端口正常处理业务流量');
  console.log('   • 端口 80 同时承担 HTTP-01 验证和重定向功能');
  console.log('   • 端口占用时自动重试，不会直接崩溃\n');

  console.log('========================================');
  console.log('  Example: Certificate Request');
  console.log('========================================\n');

  console.log('Regular domain (HTTP-01):');
  console.log('  await manager.requestCertificate({');
  console.log('    domains: ["example.com", "www.example.com"],');
  console.log('    challengeType: "http-01",');
  console.log('  });\n');

  console.log('Wildcard domain (DNS-01 enforced):');
  console.log('  await manager.requestCertificate({');
  console.log('    domains: ["*.app.example.com", "app.example.com"],');
  console.log('    challengeType: "dns-01",  // even if you put "http-01", it will be overridden');
  console.log('  });\n');

  console.log('Get service status for monitoring:');
  console.log('  const status = await manager.getManagedStatus();');
  console.log('  console.log(JSON.stringify(status, null, 2));\n');

  console.log('Status output includes:');
  console.log('  - certificates[].daysUntilExpiry');
  console.log('  - certificates[].needsRenewal');
  console.log('  - certificates[].renewalTask.lastError');
  console.log('  - certificates[].renewalTask.nextAttemptAt');
  console.log('  - certificates[].renewalTask.failureHistory[]');
  console.log('  - renewalScheduler.tasks[] with full history');
  console.log('  - tls.stats with handshake counters\n');

  console.log('[Cleanup] This is a demo - not starting servers in example mode.');
  console.log('In production, call: await manager.start(handler)');
  console.log('');
  console.log('✓ Demo complete');
}

exampleUsage().catch((err) => {
  console.error('Example failed:', err);
  process.exit(1);
});
