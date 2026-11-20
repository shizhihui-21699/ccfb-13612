# 邮件出站网关：不降级的传输安全

## 1. 问题

公司发给合作方的邮件在传输中走了明文。对方邮件服务器支持 TLS；攻击者在
网络里把 STARTTLS 能力从 EHLO 响应里剥掉了，发送端于是按"机会式加密"的老
规矩降级到明文。

这不是"忘了开 TLS"的问题，而是 **机会式加密（opportunistic TLS）在定义上
就允许降级** 的问题。要修它，发送端必须在发信前知道对方"要求"加密，并且
在要求满足不了的时候宁可不发。

本仓库实现这样一个网关，并且把最难的部分当作主要工作：

- 策略本身可能被攻击者伪造或抹掉（DNS 未签名时）；
- 策略会在 testing / enforce 之间合法切换，而这种切换和重放攻击长得一样；
- 对方多台 MX 证书不一致、轮换到一半；
- 队列里已经排着的邮件，在策略变化后怎么办；
- 大批收件域并发时，缓存与重试不能留下降级窗口；
- 报告要区分"有人攻击"和"对方配错了"。

## 2. 结论先行：系统承诺什么，不承诺什么

**承诺**（有测试断言，见 `internal/lab/`）：

1. 当生效策略是 `enforce` 时，明文投递**不可能**发生。这条不依赖任何一层
   的"正确性"，而是在三处独立检查：策略层给 `RequireTLS`、SMTP 客户端在
   完成投递后自检、队列在报告里核对。
2. 未认证的证据**永远不能**降低已经建立的保护等级。
3. 策略刷新失败**永远不能**延长旧策略寿命，也**永远不能**降低模式。
4. 队列中在 `enforce` 下入队的邮件，在策略变化后不会静默转为明文。
   唯一允许的明文路径是一次**经过认证的、被显式记录的**策略撤销。
5. 报告把"疑似攻击"与"对方配置错误"分成两组，前者排在前、可触发告警，
   后者不触发告警。

**不承诺**（诚实地说）：

1. 如果攻击者**从第一次取策略之前**就在网络里，且对方域名没有 DNSSEC，
   那么发送端无法区分"对方没有策略"与"攻击者抹掉了策略"。没有任何协议能
   解决它；本系统的应对是 `StrictUnknown` / `ProtectedDomains`（见 §6）。
2. 本实现假设 DNSSEC 验证器本身可信（本仓库内置一个，见 `internal/dnsx`）。
   真实部署里信任锚的管理是运维问题，不是代码问题。
3. 系统不阻止投递**到**错误的服务器——只要那台服务器能出示符合策略的证书。
   证书与策略才是边界；IP 不是。

## 3. 架构

```
     ┌──────────────┐   queue.json / API
     │   入站邮件    │───────────────┐
     └──────────────┘               ▼
                          ┌──────────────────┐
                          │  internal/queue  │  入队时冻结"承诺"
                          │  Worker.Enqueue  │  PlannedMode/Generation
                          └────────┬─────────┘
                                   │ 投递前取策略
                                   ▼
     ┌────────────────────────────────────────────┐
     │ internal/policy  Engine                    │
     │  ├─ DANE (RFC 7672)  ← internal/dnsx 验证  │
     │  └─ MTA-STS (RFC 8461) ← internal/sts      │
     │  规则 R1–R5，见 §4                          │
     └───────────────┬────────────────────────────┘
                     │ model.Policy + MX 列表(已解析)
                     ▼
     ┌────────────────────────────────────────────┐
     │ internal/smtpc  Client                     │
     │  EHLO → STARTTLS → 证书按策略校验 →       │
     │  …→(BeforeDATA 复查)→ DATA                 │
     └───────────────┬────────────────────────────┘
                     ▼
     ┌──────────────────────────┐   ┌─────────────────────┐
     │ internal/classify        │──▶│ internal/report     │
     │ 攻击 / 配置 / 轮换 / 不可用│   │ 人读 + JSON          │
     └──────────────────────────┘   └─────────────────────┘
```

`internal/lab` 不是生产代码：它构建一个**真实的**私网——真 DNSSEC 签名的
区域、真证书、真 SMTP 服务器、真中间人——供测试和 `-simulate` 使用。

## 4. 核心规则

### R1 没有认证证据，不得降低保护等级

每次观测（observation）都与已接受的记录（`policy.Record`）比较：

| 观测 | 处理 |
|---|---|
| 更强（testing→enforce） | **立即**接受，无需认证。攻击者用更强策略只能让我们更严格。 |
| 相同 | 刷新寿命；MX 集合或 policy id 变化时 bump generation。 |
| 更弱且 DNSSEC 认证 | 接受，但**等到旧策略过期**才生效。 |
| 更弱且未认证 | 需两次相同观测跨越 `StabilizationWindow`，且旧策略已过期。 |

"更弱且未认证"这一条是抵御**重放**的关键：攻击者可以重放一份旧的、合法
签名的 `testing` 策略文件。稳定窗口要求同一个弱观测持续存在一段时间，
单次注入做不到。代价是真实的策略撤销会延迟生效——这是有意的取舍。

### R2 不存在 ≠ 允许

`_mta-sts` 记录缺失时，**DNSSEC 验证结果**决定它的含义：

- `secure`（有签名的否定证明）：对方确实没发布策略 → 按无策略处理；
- `bogus`：签名区域里的答案验证失败 → 被篡改或被破坏，**绝不当成"没有
  策略"**；
- `indeterminate`：查不到 → 同样是失败，不是缺席。

一个普通 stub resolver 会把这三种情况都压成"空答案"，这一步压缩正是攻击
者把强制策略变成机会式明文的入口。`internal/dnsx` 存在的唯一理由就是拒绝
这个压缩。

### R3 刷新失败不降低模式，也不延长寿命

策略主机不可达、文件解析失败、DNS 超时——全部**不改变**已接受的策略，也
**不更新 `ExpiresAt`**。

后半句是容易被忽略的：如果失败时顺手续期，攻击者只要持续黑洞策略主机，
就能让一份过期策略永远"新鲜"，同时把真实的故障藏在健康的缓存后面。测试
`TestStaleEnforceIsKeptWhenRefreshFails` 断言了这一点。

超过 `StaleGrace` 后仍然**不降级**：投递被挂起（`Blocked`），报告升级。

### R4 每一次策略变化都带 generation

投递记录它规划时用的 generation；`BeforeDATA` 回调在信封已接受、正文尚未
发送的那一刻复查。

这个检查**不是**"generation 变了就中止"——日常续期和升级不该打断在途邮件。
它只在**本次传输将变得不合规**时中止：

- 模式被削弱且未经许可；
- 当前 MX 不再被策略允许；
- 该 MX 的 TLSA 记录变了。

放在 DATA 之前而不是 MAIL FROM 之前，是因为 DATA 之后正文才真正离开本机。
中止于 DATA 前，代价只是一次重试。

### R5 升级即时，降级迟缓

这条不对称是整个设计的支点。见 R1 的表格。

## 5. 队列：策略变化后，排队的邮件怎么办

`queue.Worker.Enqueue` 在入队时把 `PlannedMode` 与 `PlannedGeneration`
**冻结**进条目。这是"我们对发件人承诺了什么"的记录，此后不变。

投递时（`deliver`）：

```
effMode := 当前策略模式
if PlannedMode == enforce && effMode < enforce:
    if 该降级不是"被认可的"（sanctioned）: 挂起，报告为 refused downgrade
    else: released = true    // 显式、记录在案的放松
needTLS := effMode == enforce || (PlannedMode == enforce && !released)
```

"被认可的降级"只有两种 reason：`authenticated_downgrade`（DNSSEC 认证过）
和 `downgrade_stabilized`（稳定窗口满足）。两者都由策略引擎写入 history。

四种情形都有测试：

| 情形 | 结果 |
|---|---|
| enforce 入队 → 记录被 MITM 抹掉 | 保持挂起，**不发明文** |
| enforce 入队 → 域名认证地撤销 enforce | 明文送出，`Released=true`，报告里有 `enforce_released` 事件 |
| testing 入队 → 域名升到 enforce | 重新规划，**不发明文** |
| 投递中策略被削弱（未认可） | `BeforeDATA` 中止，正文未发 |

## 6. 攻击者在第一次取策略之前就在网络里

这是问题描述里最难的一条，也没有完全令人满意的答案。

**为什么难**：如果 `_mta-sts` 记录从未被认证地见过，那么"对方没策略"与
"攻击者抹掉了策略"在发送端是同一个观测。任何声称能区分二者的设计，要么
在撒谎，要么在偷偷依赖带外的信任。

**本系统的三种应对，按代价递增**：

1. **默认（无配置）**：未认证的"无策略"按无策略处理，走机会式加密。这与
   所有现有 MTA 一致。报告会明确标注"policy lookups not DNSSEC-secure"的
   数量。
2. **`-protect domain1,domain2`**：对这些域名（及子域）启用严格模式。没有
   认证策略就挂起，不猜。这是**实践中最好的中间点**：把严格性用在真正
   重要的合作关系上。
3. **`-strict-unknown`**：全局严格。代价是对所有确实不发布策略的域名都会
   延迟投递。可以接受的前提是出站流量面窄、且投递延迟可容忍。

源码里 `policy.Options.StrictUnknown` / `ProtectedDomains`，测试
`TestStrictUnknownHoldsWithoutAuthenticatedPolicy`。

**推荐组合**：`-protect` 列出关键合作方 + 全量报告。先看报告里哪些域名
长期是 `insecure`，再决定是否为它们承担严格模式的代价。

## 7. 缓存、并发与不留窗口

**单飞（singleflight）**：同一域名的并发解析只触发一次策略获取。否则一批
邮件会变成对合作方策略主机的拉取风暴，而每次拉取都是一次看到不同答案的
机会。测试 `TestConcurrentResolveSingleFetch`（64 并发 → 恰好 1 次获取）。

**有界并发**：`MaxConcurrentFetch` 限制同时进行的策略获取。

**MX 在策略时解析，投递时不解析**：`policy.Resolution` 携带已解析的地址
列表。在"策略已检查"与"套接字已打开"之间做 DNS 查询，就是一个攻击者可以
利用的降级窗口。`model.MXHost` 的注释写明了这一点。

**TTL 下限**：缓存条目至少保留一分钟，避免短期 TTL 变成查询洪水；上限
六小时，避免长期不复查。`MaxAge=` 本身也封顶 7 天。

**失败不放大**：`TestNoFetchStormOnFailure`——50 个并发过期只产生 1 次
获取。

## 8. 证书与多 MX

- **MTA-STS**：`mx:` 模式列表。`*.` 只匹配一个标签（RFC 8461 §4.1），
  有两标签的测试。不在列表里的 MX **直接丢弃**，不是"排到最后"——尝试它
  们不是回退，就是降级。
- **DANE（RFC 7672）**：TLSA 记录**按 MX 主机名**分别保存
  （`Policy.TLSA map[string][]TLSARecord`）。把整个域名的 TLSA 集合拍平成
  一个，会把"每台主机用自己的证书"变成"任意主机的证书都行"，这是真实的
  安全削弱。`smtpc` 用 `msg.TLSA[strings.ToLower(mxHost)]` 取记录。
- **DANE 仅当 MX 与 TLSA 都是 DNSSEC secure 时生效**（RFC 7672 §2.2.1）。
  TLSA 为 bogus 时，**不**回退到 MTA-STS：签名区域里验证失败的 TLSA 是最强
  的 DNS 攻击信号，退到更弱的机制等于奖励攻击者。
- **半轮换**：证书只匹配**同域名的兄弟 MX** 时，分类为 `rollover_in_progress`
  （不告警、可重试）；匹配未知 CA 时分类为 `attack_suspected`。区分依据是
  **证书里出现的主机名**，不是错误文本——错误字符串不稳定。

## 9. 区分攻击与配置错误

`internal/classify` 输出 `FaultClass` + `Confidence` + 信号列表。信号被
刻意选成**单个在线攻击者难以孤立伪造**，且可以叠加：

| 信号 | 指向 | 权重 |
|---|---|---|
| `policy_dns_bogus`（签名区答案验证失败） | 攻击 | 0.90 |
| `policy_vanished_unauthenticated`（曾 secure，现无验证的缺席） | 攻击 | 0.85 |
| `starttls_stripped_after_prior_tls`（曾完成验证过的 TLS） | 攻击 | 0.95 |
| `cert_changed_since_clean`（叶证书指纹变了） | 攻击 | 0.90 |
| `cert_unknown_ca` | 攻击 | 0.60 |
| `cert_matches_sibling_mx` | 轮换 | 0.80 |
| `shared_host_failure`（同一主机害了 ≥2 个收件域） | 配置 | 0.75 |
| `cert_expired` | 配置 | 0.70 |
| `smtp_530`（入站端口要认证） | 配置 | 0.80 |
| `partial_mx_failure`（部分 MX 正常） | 轮换 | 0.70 |

**最关键的两个判别器**：

- **历史**：`HostHistory` 记录每台 MX 上次**成功完成验证过的 TLS** 时的证书
  指纹与时间。一个先前从未在场的攻击者无法复现这次成功的会话。这让
  `starttls_stripped_after_prior_tls` 成为几乎决定性的信号。
- **跨域**：`SharedHostFailures` 统计同一台 MX 正在害多少个**别的**收件域。
  定向劫持不会伤到别的域名；配错的服务器会伤到所有人。

置信度算法见 `aggregate`：各类得分之和取占比，再乘以绝对证据量的温和函数，
上限 0.99。**一个弱信号读起来就不是确定的**（`TestConfidenceIsBoundedAndMonotone`）。

**为什么这个区分重要**（取舍本身）：
- 把每台坏服务器都叫"攻击"→ 告警疲劳 → 有人把检查关掉 → 真攻击被放过；
- 把每次攻击都叫"配置错误"→ 无限重试 → 这正是本系统要防的降级。

所以 `Retry` 与 `Escalate` 是两个独立字段：配置错误可重试、不告警；攻击
不可在同路径重试、立即告警。

## 10. 模拟环境与中间人手法（`internal/lab`）

全部是真实的实现，不是 mock：

- `lab.NewCA`：私 CA，签发叶子证书，可设有效期、SAN、CA 标志。
- `lab.Zone`：真实签名区域（ECDSA P-256，KSK 签 DNSKEY、ZSK 签其余），
  真实 NSEC 否定证明。`dnsx` 对它做真实的链式验证。
- `lab.DNSServer`：UDP+TCP 权威服务器。
- `lab.DNSAttacker`：可针对**单个域名**的转发型中间人，模式：
  - `AttackerStripPolicyTXT`：抹掉记录（签名区 → 验证器判 bogus）
  - `AttackerStripAllSigs`：抹掉所有 RRSIG
  - `AttackerForgeNXDOMAIN`：伪造空 NXDOMAIN
  - `AttackerStripDANE` / `AttackerRewriteTLSA`
- `lab.Server`：真实 SMTP 服务器，可配置：不广告 STARTTLS（能力剥离）、
  STARTTLS 后断开握手、454 拒绝、530 要认证、固定 5xx、指定证书、最低
  TLS 版本。
- `lab.PolicyServer`：可运行时替换 body 的 HTTPS 策略主机。
- `lab.Clock`：手动时钟，用于推进策略寿命与稳定窗口，无需 sleep。

`-simulate` 一次性演示四种结局，且它跑的是**生产代码路径**（`queue.Worker`
+ `smtpc.Client`），不是另写一遍逻辑：

```
good.example     delivered_tls   fault=none                     conf=0.50
broken.example   deferred        fault=remote_misconfiguration  conf=0.68
roll.example     deferred        fault=rollover_in_progress     conf=0.54
strip.example    blocked         fault=policy_unavailable       conf=0.90
```

`Outcome` 与 `Fault` 回答不同问题：Outcome 是"邮件怎么了"，Fault 是"为什么"。
一台**坏掉的**服务器导致明文被拒，仍然是 `deferred`（挂起、会重试）；把它
记成 `blocked` 会告诉运维"这个域名不可达"，而这是错的。只有策略层面无法
满足、或疑似攻击，才记为 `blocked`。

## 11. 取舍清单（按重要性）

1. **安全 > 投递率。** 策略满足不了就挂起。这是产品定位，不是 bug。
2. **降级要等，升级不等。** 合法撤销 enforce 会有最长一个 `max_age` 的延迟。
   我们接受这个延迟，换取"签名回滚不能立刻抽走已排队邮件的保护"。
3. **稳定窗口是真实成本。** 未认证的合法降级要等满窗口。默认 24 小时。
4. **需认证证据才降级。** 无 DNSSEC 的域名在记录消失时**保持** enforce 直到
   宽限期，而不是回落。代价是该域名长期不修就会持续挂起。
5. **每次取策略都走 HTTPS + 证书校验 + 拒绝重定向。** 一次重定向就能让被
   攻陷的策略主机把策略托管到别处去；RFC 8461 §3.3 本来就禁止跟随。
6. **STARTTLS 握手失败后绝不回落明文**，哪怕策略只是机会式的。RFC 3207
   §4.2 要求丢弃连接，而安全理由更强：`TLS 失败就发明文` 正是攻击者破坏
   握手想要诱导的行为。代价是：TLS 栈坏掉的合作方会投递失败（可重试），
   而不是静默收到明文。这是有意的——静默明文正是本系统要消灭的东西。
7. **单飞 + 有界并发。** 宁可让一个域名的解析慢一点，也不发拉取风暴。
8. **报告宁可有噪声也不要沉默。** 没有信号就写"证据不足"，不写"安全"。
9. **`mode: none` 视为非法。** RFC 8461 只定义 testing/enforce。声称 none
   的策略文件要么坏了要么在试着把我们谈下来，两种都不可用。
10. **失败不续期。** 见 R3；表面的"缓存健康"比真实故障更危险。
11. **不跟随 CNAME。** 策略查找里出现 CNAME 直接判 indeterminate——跟随它
    是一个额外的攻击面，而 MTA-STS/DANE 的名字不需要它。

## 12. 已知限制

- DNSSEC 验证器是内置的最小实现，支持 ECDSA/Ed25519/RSA 的常见组合与
  NSEC/NSEC3；未覆盖算法轮换、CDS/CDNSKEY 自动更新、多签名者。生产部署
  应前置一个经过审计的验证解析器，本仓库的 `dnsx` 证明了"验证在本进程内
  完成"是可行的，也给出了 `bogus`/`insecure`/`indeterminate` 三态必须分开
  的理由。
- `internal/dnsx` 的 NSEC3 覆盖判断是简化实现（`Match`/`Cover` 来自
  miekg/dns），未处理 opt-out 的全部细节。
- 队列目前是内存与 JSON 目录两种存储；真实部署需要事务性存储与崩溃恢复。
- 报告的分类器是规则加权的。它刻意保持可解释；换成 ML 会失去"为什么"。

## 13. 运行

```sh
go test ./... -race            # 全部测试，含竞态检测
go run ./cmd/gateway -simulate # 一次敌意网络的端到端演示

# 真实队列（需要信任锚）
GATEWAY_TRUST_ANCHORS=anchors.json \
  go run ./cmd/gateway -queue queue.json -report out.txt -json out.json \
  -protect partner.example
```

`anchors.json` 形如 `{".": ["example. 3600 IN DNSKEY 257 3 13 ..."]}`。
没有锚点时代码**拒绝启动**——否则每个查找都是 insecure，整条强制路径会
静默变成机会式。
