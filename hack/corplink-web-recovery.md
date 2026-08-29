# corplink-web 隧道探测与自动恢复方案

本文记录社区镜像 `riba2534/corplink-web:latest` 的 WireGuard 隧道探测与自动恢复机制，
以及 2026-08-26 在隔离 Docker 容器中对 CN-LF6 进行定向故障注入的验证结果。

这份记录用于后续向 `corplink-rs` 移植恢复能力。它不是社区项目源码的逐行说明：分析时
上游源码仓库不可访问，函数关系来自镜像内未剥离的 Go/DWARF 符号、ARM64 反汇编和运行
日志，恢复行为则经过实际故障注入验证。

## 1. 分析对象

分析使用的镜像信息：

```text
image:    riba2534/corplink-web:latest
digest:   sha256:c599b78fdb52592b4a99fd73742db2619845dbd089f04cf740d29317b21784da
image id: sha256:e6c10e61d55ae01f0064cf39c4fa3b4e38edffa7ca973bc954c65c53806cc20e
created:  2026-08-19T08:38:41Z
revision: ac15bbfd5841c8112a5309cbfa72922637bc0f56
source:   https://github.com/riba2534/corplink-web
```

镜像运行的是 Go 编写的 `corplink-web`。它将 WireGuard 数据面接到 gVisor 用户态
netstack，并在容器内暴露 SOCKS5，不创建宿主机内核 TUN，也不修改宿主机路由或 DNS。

因此它能处理 WireGuard/netstack 数据面失效，但不能直接证明或修复 macOS `utun`、
系统路由或系统 DNS 自身的问题。

## 2. 主要组件

镜像二进制保留了以下关键函数：

| 组件 | 主要职责 |
|---|---|
| `vpnmgr.(*Manager).runProbe` | 周期性收集隧道与 underlay 信号 |
| `vpnmgr.(*Manager).probeAccess` | 获取近期真实访问结果，避免无条件重建 |
| `vpnmgr.probeTunnelAfter` | 主动验证隧道 DNS 与路径 |
| `vpnmgr.probeUnderlay` | 独立验证控制面/普通网络是否可达 |
| `availabilityDetector.observe` | 累积双信号失败并作去抖判断 |
| `vpnmgr.(*Manager).requestRecovery` | 串行化恢复请求并应用冷却/预算限制 |
| `vpnmgr.(*Manager).runRecovery` | 执行分层恢复流程 |
| `vpnmgr.(*Manager).tryCurrentRecoveryPath` | 优先修复当前连接，避免立即换节点 |
| `corplink.(*NetstackDevice).RepairTransport` | 修复 WireGuard UDP transport |
| `vpnmgr.(*Manager).tryRecoveryCandidates` | 当前连接修复失败后尝试候选连接 |
| `connectCandidateForRecovery` | 准备候选节点连接，但尚不替换当前连接 |
| `validateAndCommitCandidateForRecovery` | 验证候选隧道后原子提交 |
| `restoreRecoverySelectionLocked` | 恢复失败时回滚节点选择状态 |

恢复不是简单地“握手超时后退出”，而是一个有检测、去抖、underlay 判断、原地修复、
完整重建、验证提交和冷却预算的状态机。

## 3. 探测循环

从 `internal/vpnmgr/probe.go` 的 `runProbe` 反汇编可还原出：

- 连接建立后首次探测等待 10 秒。
- 后续每 5 秒执行一次探测循环。
- 单次 tunnel/underlay 子探测使用约 5 秒超时。
- 探测结果与当前连接代次绑定；连接已经被替换时，旧结果会被丢弃。

逻辑可以概括为：

```text
每 5 秒：
  1. 读取近期 SOCKS/隧道访问结果。
  2. 必要时主动探测 VPN DNS 和隧道路径。
  3. 若隧道不可用，再单独探测控制面 underlay。
  4. underlay 不可用：保留现有隧道，不误触发重建。
  5. underlay 可用：把 DNS/path 两类结果交给 availabilityDetector。
  6. 判定器确认持续故障后，提交异步 recovery 请求。
```

underlay 区分非常重要。整体断网时实际日志为：

```text
probe: tunnel unavailable but control-plane underlay is down; preserving tunnel
```

这样可以避免 Wi-Fi 切换、睡眠唤醒或普通网络抖动时反复调用 VPN 控制面和重建 peer。

## 4. 双信号去抖判定

`availabilityDetector.observe` 分别维护 DNS 和 path 两组状态：

- 成功信号会清空对应失败计数和首次失败时间。
- 相邻观察间隔超过 90 秒时，整组历史状态重置，避免使用过期失败样本。
- 每类信号至少累计 3 次失败。
- 每类信号从首次失败到当前失败都必须跨越至少 30 秒。
- DNS 和 path 两类条件必须同时成立，才返回 `needsRecovery=true`。

即使探测循环每 5 秒执行，恢复也不会在一次超时后立即发生。实际触发延迟还受真实访问
快照和 path 探测启动时机影响。本次 LF6 定向故障中，从开始屏蔽 WireGuard endpoint 到
接受恢复请求约为 124 秒。

触发前的日志显示两类信号独立累积：

```text
probe: both tunnel signals failed (dns=22 path=1, window=30s)
probe: both tunnel signals failed (dns=23 path=2, window=30s)
...
probe: both tunnel signals failed (dns=28 path=7, window=30s)
recovery: accepted availability request
```

## 5. 分层恢复流程

可观察到的恢复顺序如下：

```text
availability request
  -> 等待短暂恢复延迟
  -> RepairTransport(current connection)
  -> 在限定时间内验证当前 tunnel
  -> 成功：保留当前 peer 和分配地址
  -> 失败：申请 automatic rebuild budget
  -> 准备 recovery candidate
  -> 连接并验证候选 tunnel
  -> 原子提交候选连接
  -> 关闭旧连接
```

### 5.1 Transport repair

第一层调用 `NetstackDevice.RepairTransport`。它在持锁状态下检查设备生命周期，然后调用
底层 `repairTransport` 重建或重新绑定 WireGuard UDP transport，而不立即重新申请 VPN
peer。

本次故障中，因为测试规则仍在拒绝 LF6 UDP/80，修复阶段按预期超时：

```text
recovery: event=transport_repair action=start seq=3 node_id=108 protocol=2
recovery: event=transport_repair action=timeout seq=3
```

### 5.2 Full rebuild

transport repair 失败后，Manager 申请一次自动重建预算。本次日志显示冷却窗口为 10 分钟：

```text
recovery: event=rebuild_budget action=admit source=availability seq=3 \
  round=1 budget_round=1 next_allowed=2026-08-26T14:55:20Z
```

随后它为当前固定节点创建候选连接，完成控制面建连、peer 配置和 tunnel 验证后才提交：

```text
recovery: event=candidate_attempt seq=3 budget_round=1 kind=full \
  candidate=1/1 node_id=108 protocol=2
netstack: local addrs=[10.255.205.251 ...], vpn dns=[10.8.8.18], mtu=1280
recovery: event=candidate_commit seq=3 budget_round=1 kind=full node_id=108
```

重建前分配地址是 `10.255.192.240`，提交后变为 `10.255.205.251`，证明这里发生的是完整
控制面重连和 peer 替换，而不只是 WireGuard 自己重新发送 handshake。

整个过程中 `corplink-web` 容器进程 PID 保持不变。

## 6. 节点选择与恢复

当前镜像的节点选择配置有一个容易误用的细节：

- 固定节点：设置非零 `vpn_server_id`，`vpn_select_strategy` 使用空字符串。
- 自动选点：`vpn_server_id=0`，`vpn_select_strategy="auto"`。
- `vpn_select_strategy="manual"` 不受支持，会报 `unsupported strategy "manual"`。

固定节点恢复时，candidate 可以仍然是原节点。本次测试设置 CN-LF6（当时 ID 108），
full rebuild 后仍提交到 `node_id=108`。自动选点模式还包含候选筛选、测速和自动切换流程，
对应 `runAutoSwitchRecovery`、`selectRepairCandidates` 等函数。

节点 ID、IP 和协议是服务端动态数据，不应把本次的 ID 108 或 endpoint 固化到实现中。

## 7. 隔离故障注入方法

测试必须使用独立配置、device id、WireGuard 密钥和 Cookie 文件，并只暴露 SOCKS 端口；
不要挂载生产配置，也不要让测试容器修改宿主机路由或 DNS。

基线验证：

```bash
curl --socks5-hostname 127.0.0.1:12347 \
  --max-time 15 -o /dev/null -w 'http=%{http_code} total=%{time_total}\n' \
  https://code.byted.org/
```

为了只阻断 WireGuard UDP、同时保持容器控制面 underlay 可用，可以启动一个共享目标容器
network namespace 的临时 helper：

```bash
docker run -d --rm --name corplink-netfault \
  --network container:corplink-web-test \
  --cap-add NET_ADMIN alpine:latest \
  sh -lc 'apk add --no-cache iptables >/dev/null && sleep 600'

docker exec corplink-netfault \
  iptables -I OUTPUT 1 -p udp -d <VPN_ENDPOINT_IP> --dport <VPN_PORT> -j REJECT
```

解除故障时必须精确删除同一规则，再停止 helper：

```bash
docker exec corplink-netfault \
  iptables -D OUTPUT -p udp -d <VPN_ENDPOINT_IP> --dport <VPN_PORT> -j REJECT
docker stop corplink-netfault
```

本次 CN-LF6 实测结果：

- 故障前代理请求 12/12 成功，耗时约 0.17–0.60 秒。
- 只屏蔽 WireGuard endpoint 时，SOCKS 能接受连接，但 tunnel DNS/path 持续超时。
- 探测器确认双信号持续失败后接受 recovery。
- transport repair 失败后自动 full rebuild。
- 解除故障后首个请求约 0.89 秒成功，后续回到约 0.15 秒。
- 恢复后连续验证 6/6 成功。

## 8. 与当前 corplink-rs 的差距

截至本记录，`corplink-rs` 的 `UAPIClient::check_wg_connection` 主要读取 WireGuard
`last_handshake_time_sec`：

- 以 5 分钟为检查/过期尺度。
- 握手超过阈值后返回。
- `main` 随后执行 disconnect、清理路由/DNS 并退出。

稳定版 `bytedance-6.5.2` 没有社区 Web 方案中的以下能力：

1. DNS 与真实路径双信号探测。
2. tunnel 与控制面 underlay 分离判断。
3. 失败去抖与连接代次校验。
4. 原地 RepairTransport。
5. 候选连接先验证、后原子提交。
6. 自动重建预算、冷却和并发恢复串行化。

`preview/tunnel-recovery` 从 `bytedance-6.5.2` 分叉，已经加入第一版可测试实现：

- 握手年龄 + 必须经过隧道的 HTTP 请求作为双信号；并非逐字复刻 Web 的 DNS/path
  两个探针，但能避免仅凭握手时间误判。
- 首次延迟 10 秒、每 5 秒探测、至少 3 次失败且窗口至少 30 秒、超过 90 秒断档重置。
- 隧道双信号失败后单独探测控制面 underlay；underlay 失败时重置观察窗口并保留隧道。
- transport repair 通过 UAPI 将 `listen_port` 设为新的临时端口，触发 wireguard-go
  `BindUpdate`，同时以 `update_only` 重设现有 peer endpoint；随后主动验证最多 30 秒。
- repair 失败后清理 TUN/DNS，并以同一 config/Cookie/device/key `exec` 新进程完成重建。
- 用环境变量跨 `exec` 保留下一次允许完整重建的时间，默认冷却 10 分钟。
- SOCKS5/netstack 的 HTTP 探测强制使用本机 `socks5h`，已用模拟 SOCKS 服务验证域名
  确实交给隧道内 resolver，而不是宿主 DNS。

这一版仍和社区实现有两个明确差异：它没有在旧连接存活时并行准备 candidate，也没有
candidate 验证成功后的原子提交；full rebuild 是先安全撤销旧 TUN/DNS 再 `exec`，因此
会有短暂中断。后续若要做到同等无缝切换，需要扩展 libwg，使同一进程能同时拥有带独立
generation 的两个 device/netstack，而不是现在的全局单例 `wgDevice`。

另外，macOS TUN 模式还必须独立处理系统级故障。即使移植上述恢复状态机，也不能让
失效的 `utun` 路由或 VPN DNS 持续劫持整机网络。建议把实现拆为两个层次：

- 数据面恢复：参考本文实现 probe、underlay 判断、transport repair 和 full rebuild。
- 宿主保护：在确认当前 generation 失效后，原子撤销旧路由/DNS；新 candidate 验证成功后
  再安装新路由，并确保任何失败路径都能回滚。

## 9. 推荐的移植边界

建议先引入与平台无关的恢复控制器，再由 TUN 和 netstack 分别实现数据面操作接口：

```text
TunnelHealthProbe
  - probe_dns()
  - probe_path()
  - probe_underlay()

TunnelTransport
  - generation()
  - repair_transport()
  - prepare_candidate()
  - validate_candidate()
  - commit_candidate()
  - rollback_candidate()
```

恢复控制器应满足：

- 同一时间最多一个 recovery owner。
- 用户主动 disconnect/connect 能取消正在运行的 recovery。
- 每个异步结果都检查 connection generation，禁止旧结果覆盖新连接。
- repair 和 rebuild 都有独立超时。
- candidate 未验证前不破坏当前连接。
- 自动重建有预算和冷却，防止服务端或本地网络长期异常时形成重连风暴。
- 日志使用结构化事件，至少包含 source、sequence、round、node、protocol、action 和结果。

## 10. 结论与限制

社区方案真正提供了“持续探测后自动修复”，不是单纯依赖 WireGuard persistent keepalive：

1. 先确认 tunnel 双信号持续失败。
2. underlay 也失败时保留隧道。
3. underlay 正常时先 RepairTransport。
4. 修复失败后在预算内完整重建并验证候选连接。

这能解释 `corplink-web` 在 WG transport 失效场景下比“握手超时后退出”的实现更稳定。
但由于 Web 版本身不使用 macOS 内核 TUN，这个结果不能排除 macOS 路由/DNS 故障；两类
问题需要分别监测和恢复。
