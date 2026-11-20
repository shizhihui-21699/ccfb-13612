# 邮件出站网关：不降级的传输安全

一个 Go 写的邮件投递网关。发信前用 **DNSSEC 验证过的** MTA-STS / DANE 策略
判断对方是否要求加密；要求满足不了就挂起，不发明文。

设计、取舍、已知限制见 **[docs/DESIGN.md](docs/DESIGN.md)**。

## 快速开始

```sh
go test ./... -race               # 全部测试，含竞态检测
go run ./cmd/gateway -simulate    # 在进程内搭一个敌意网络并跑生产代码路径
```

`-simulate` 输出四种被区分开的结局：

```
deliveries: 4
  over policy-compliant TLS : 1
  cleartext                 : 0
  blocked                   : 2
  deferred                  : 1

REMOTE MISCONFIGURATION (1)   broken.example   对方 TLS 栈坏了，可重试
ROLLOVER IN PROGRESS    (1)   roll.example     证书轮换到一半，等它完成
POLICY UNAVAILABLE      (1)   strip.example    策略被抹且该域名是受保护域名，挂起
```

真实队列：

```sh
GATEWAY_TRUST_ANCHORS=anchors.json \
  go run ./cmd/gateway -queue queue.json \
    -report out.txt -json out.json -protect partner.example
```

没有信任锚时网关**拒绝启动**——否则每个查找都是 insecure，整条强制路径会
静默退化成机会式加密。

## 目录

| 路径 | 作用 |
|---|---|
| `internal/model` | 共享类型：策略、模式、观测、判定 |
| `internal/dnsx` | 验证 DNSSEC 的解析器（secure/insecure/bogus/indeterminate 四态分开） |
| `internal/sts` | MTA-STS 记录与策略文件获取、解析 |
| `internal/dane` | RFC 6698 TLSA 匹配（含 RFC 7672 的每主机规则） |
| `internal/policy` | 策略引擎：规则 R1–R5，缓存，单飞，负缓存 |
| `internal/smtpc` | ESMTP 客户端：在 enforce 下不可能发明文 |
| `internal/queue` | 投递队列：入队冻结承诺，DATA 前复查 |
| `internal/classify` | 攻击 / 配置错误 / 轮换 的区分 |
| `internal/report` | 人读与 JSON 报告 |
| `internal/lab` | 敌意网络模拟器（真 DNSSEC、真证书、真中间人）——**非生产代码** |
| `cmd/gateway` | 二进制入口 |

## 核心不变量（均有测试）

1. `enforce` 下明文投递不可能发生（`TestNoCleartextUnderEnforceAcrossScenarios`）。
2. 未认证的证据不能降低已有保护（`TestUnauthenticatedDowngradeNeedsStabilization`）。
3. 刷新失败不降级、不续期（`TestStaleEnforceIsKeptWhenRefreshFails`）。
4. 队列中 enforce 入队的邮件不会被静默降级（`TestQueuedEnforceThenPolicyWithdrawnUnsanctioned`）。
5. STARTTLS 握手失败后绝不回落明文（`TestNoCleartextFallbackAfterFailedHandshake`）。
