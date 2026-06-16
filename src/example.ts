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
  console.log('  Provides comprehensive per-domain lifecycle status including:');
  console.log('  • currentState: unissued | issuing | issuing-failed | active | renewing | renewal-failed | expiring-soon | expired');
  console.log('  • lastOperation: type (initial-issue/renewal/force-renewal/manual-request), status, time, error');
  console.log('  • lastSuccessfulIssue / lastRenewalAttempt / lastFailure with timestamps');
  console.log('  • consecutiveRenewalFailures count and nextScheduledRenewalAt');
  console.log('  • latestOperations[]: last 5 operations (per-domain) for debugging');
  console.log('  • renewalTask with phase (checking/ordering/challenging/finalizing/installing/cleaning)');
  console.log('  • Unissued domains show stateReason explaining WHERE it got stuck');
  console.log('');

  console.log('[4/6] Heatlh Check API (getHealthCheck):');
  console.log('  Returns unified health with 5 components + warnings/criticals/summary:');
  console.log('  • manager: initialized + started');
  console.log('  • httpChallenge: port listening (probe HTTP-01 availability)');
  console.log('  • httpsDefaultCert: default cert exists AND > minDaysRemaining (14 default)');
  console.log('  • renewalScheduler: running + no domain exceeds consecutiveFailureThreshold (3 default)');
  console.log('  • storage: directory writable + cert count');
  console.log('  • top-level healthy = all 5 components healthy');
  console.log('  • Easy to integrate with Prometheus / external probes');
  console.log('');

  console.log('[5/6] Renewal History Query & Failure Preservation:');
  console.log('  ✓ getRenewalHistory(domain, limit): per-domain success+failure timeline');
  console.log('  ✓ getAllConsecutiveFailures(): global overview of problematic domains');
  console.log('  ✓ Success does NOT erase failureHistory — lastFailureSummary preserved:');
  console.log('      - beforeSuccessCount: consecutive failures before this success');
  console.log('      - lastError / lastFailedAt: last error before success saved');
  console.log('      - totalFailuresBeforeSuccess: total in run-up to success');
  console.log('  ✓ successHistory: last 20 successful renewals (serial + days remaining)');
  console.log('  ✓ Everything persisted in renewal-tasks.json (v2 format)');
  console.log('');

  console.log('[6/6] Comprehensive Hot-Switch Coverage:');
  console.log('  ✓ invalidateContextCacheForDomains(domains[]): invalidates ALL SAN entries');
  console.log('  ✓ Wildcard expansion: deleting *.example.com also deletes sub.example.com cache');
  console.log('  ✓ Reverse wildcard: deleting sub.example.com also deletes *.example.com cache');
  console.log('  ✓ Old cert removed only AFTER new cert saved + cache invalidated');
  console.log('  ✓ Default domain auto-switched if old cert was the default');
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
  console.log('  const managed = await manager.getManagedStatus();');
  console.log('  for (const d of managed.domains) {');
  console.log('    console.log(`${d.domain}: state=${d.currentState}, reason=${d.stateReason}`);');
  console.log('    console.log(`  last op: ${d.lastOperation.type} ${d.lastOperation.status}`);');
  console.log('    if (d.lastFailure) console.log(`  last failure: ${d.lastFailure.error} at ${d.lastFailure.at}`);');
  console.log('  }\n');

  console.log('Health check for Prometheus/external probes:');
  console.log('  const hc = await manager.getHealthCheck({');
  console.log('    consecutiveFailureThreshold: 3,   // >=3 consecutive failures = critical');
  console.log('    minDaysRemaining: 14,            // <14 days default cert = warning');
  console.log('  });');
  console.log('  // hc.healthy = boolean for quick check');
  console.log('  // hc.criticals[] / warnings[] / summary[] for alert messages\n');

  console.log('Per-domain renewal history for debugging:');
  console.log('  const hist = manager.getRenewalHistory("example.com", 10);');
  console.log('  console.log(`Total successes=${hist.summary.totalSuccesses}, failures=${hist.summary.totalFailures}`);');
  console.log('  console.log(`Consecutive failures now=${hist.summary.consecutiveFailures}`);');
  console.log('  for (const e of hist.entries) {');
  console.log('    console.log(`  ${e.timestamp} ${e.type} ${e.serialNumber || e.error}`);');
  console.log('  }\n');

  console.log('List domains with >=2 consecutive renewal failures:');
  console.log('  const bad = manager.getAllConsecutiveFailures();');
  console.log('  for (const b of bad) {');
  console.log('    console.log(`${b.domain}: ${b.consecutiveFailures}x failed, next=${b.nextAttemptAt}`);');
  console.log('  }\n');

  console.log('========================================');
  console.log('  Example: Phase Timeline (细粒度时间线)');
  console.log('========================================\n');

  console.log('Each renewal / certificate request tracks detailed phase timings:');
  console.log('  const task = manager.getRenewalScheduler()?.getTaskForDomain("example.com");');
  console.log('  if (task) {');
  console.log('    for (const phase of task.phaseTimeline) {');
  console.log('      console.log(`${phase.phase}: started=${phase.startedAt}, duration=${phase.durationMs}ms`);');
  console.log('      if (phase.error) console.log(`  ERROR: ${phase.error}`);');
  console.log('      if (phase.endedAt) console.log(`  ended at ${phase.endedAt}`);');
  console.log('    }');
  console.log('  }\n');
  console.log('Phases: checking → ordering → challenging → finalizing → downloading → installing → cleaning\n');

  console.log('========================================');
  console.log('  Example: Canary Deployment (灰度切换)');
  console.log('========================================\n');

  console.log('Start canary - new cert first goes to test domains only:');
  console.log('  await manager.startCanary({');
  console.log('    domains: ["test.example.com", "probe.example.com"],');
  console.log('    canarySerialNumber: "abc123...",   // new certificate serial');
  console.log('  });\n');

  console.log('Run probes to verify the canary is working:');
  console.log('  for (let i = 0; i < 5; i++) {');
  console.log('    const result = await manager.probeCanary("test.example.com");');
  console.log('    if (!result.success) {');
  console.log('      console.log("Probe failed, rolling back!");');
  console.log('      await manager.rollbackCanary();');
  console.log('      break;');
  console.log('    } else {');
  console.log('      console.log(`Probe ok: peerCert=${result.peerCertSubjectCN}, tls=${result.tlsVersion}`);');
  console.log('    }');
  console.log('  }\n');

  console.log('Check canary status:');
  console.log('  const status = manager.getCanaryStatus();');
  console.log('  console.log(`Canary active: ${status.active}`);');
  console.log('  console.log(`Probe results: ${status.successCount} success, ${status.failureCount} failures`);');
  console.log('  console.log(`Ready to promote: ${status.readyToPromote}`);');
  console.log('  console.log(`Ready to rollback: ${status.readyToRollback}`);\n');

  console.log('Promote when ready (replaces baseline for all traffic):');
  console.log('  if (status.readyToPromote) {');
  console.log('    await manager.promoteCanary();');
  console.log('    console.log("Canary promoted - all traffic now uses new cert");');
  console.log('  }\n');

  console.log('Rollback if problems detected:');
  console.log('  if (status.readyToRollback) {');
  console.log('    await manager.rollbackCanary();');
  console.log('    console.log("Canary rolled back - baseline cert restored");');
  console.log('  }\n');

  console.log('Note: During canary, baseline cert is NEVER deleted - always available as fallback\n');

  console.log('========================================');
  console.log('  Example: Prometheus Metrics (文本指标)');
  console.log('========================================\n');

  console.log('Export metrics in Prometheus text format:');
  console.log('  // HTTP handler for /metrics endpoint:');
  console.log('  app.get("/metrics", async (req, res) => {');
  console.log('    res.set("Content-Type", "text/plain; version=0.0.4");');
  console.log('    res.send(await manager.getPrometheusMetrics());');
  console.log('  });\n');

  console.log('Available metrics:');
  console.log('  - acme_certificate_days_remaining{domain,serial,issuer}');
  console.log('  - acme_certificate_expires_at_timestamp{domain,serial}');
  console.log('  - acme_renewal_consecutive_failures{domain}');
  console.log('  - acme_tls_handshakes_total / successful / failed');
  console.log('  - acme_tls_sni_matches_total / sni_fallback_total / sni_mismatch_total');
  console.log('  - acme_tls_canary_hits_total / canary_misses_total');
  console.log('  - acme_challenges_served_total');
  console.log('  - acme_canary_active / success_count / failure_count');
  console.log('  - and many more...\n');

  console.log('========================================');
  console.log('  Example: Default Cert Switch Verification');
  console.log('========================================\n');

  console.log('After renewal, verify default certificate is live:');
  console.log('  const probe = await manager.probeDefaultCertificate();');
  console.log('  if (probe.success && probe.actualSerial === probe.expectedSerial) {');
  console.log('    console.log(`✓ Switch verified: ${probe.domain} now uses serial ${probe.actualSerial}`);');
  console.log('    console.log(`  Subject: ${probe.actualSubject}`);');
  console.log('    console.log(`  Valid until: ${probe.validTo}`);');
  console.log('  } else {');
  console.log('    console.log(`✗ Switch NOT verified: expected=${probe.expectedSerial}, actual=${probe.actualSerial}`);');
  console.log('    console.log(`  Error: ${probe.error}`);');
  console.log('  }\n');

  console.log('Important: Non-SNI connections and SNI-mismatch fallbacks automatically');
  console.log('use the latest default certificate after renewal. No cache staleness.\n');

  console.log('[Cleanup] This is a demo - not starting servers in example mode.');
  console.log('In production, call: await manager.start(handler)');
  console.log('');
  console.log('✓ Demo complete');
}

exampleUsage().catch((err) => {
  console.error('Example failed:', err);
  process.exit(1);
});
