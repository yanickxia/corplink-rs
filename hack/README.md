# Android CorpLink 控制流抓取指南

本文说明如何在 macOS + 已 Root 的 Android/Genymotion 环境中，使用
Frida 和 [`httpdump.py`](./httpdump.py) 抓取 CorpLink 的 HTTPS 控制流量。

社区 `corplink-web` 镜像的隧道探测、transport repair 和完整重建机制记录在
[`corplink-web-recovery.md`](./corplink-web-recovery.md)。

请只分析你有权测试的设备、应用和账号。抓取结果可能包含登录态、Cookie、
令牌、内部地址和 VPN 配置，应按敏感数据处理。

## 1. 最终方案

目标是抓取 CorpLink 的控制流量，例如登录、节点列表、`/vpn/conn` 和
`/vpn/report`，而不是 VPN 隧道承载的用户流量。

最终采用进程内抓取：

1. Frida 注入目标进程。
2. Hook `libssl.so` 的 `SSL_write` 和 `SSL_read`。
3. 在 TLS 加密前、解密后取得明文字节。
4. `httpdump.py` 自动解析 HTTP/1.1 和 HTTP/2/HPACK。
5. 自动发现并附加主进程以及 `:channel`、`:vpn` 等子进程。

这个方案不修改网络路径，因此：

- 不需要设置 Android 全局 HTTP 代理。
- 不需要 mitmproxy WireGuard 模式。
- 不需要 iptables 透明代理。
- 不会与目标 VPN 的 Android `VpnService` 冲突。
- 不依赖 tcpdump 才能看到 HTTP 明文。

mitmproxy CA 系统证书对本方案不是必需条件。

## 2. 环境要求

- macOS。
- 已 Root 的 Android 模拟器；当前环境使用 Genymotion。
- Mac 已安装 `adb` 和 Python 3。
- 模拟器能够正常联网，且没有遗留的系统代理或透明代理规则。
- Frida 客户端与 `frida-server` 版本完全一致。
- `frida-server` 架构与模拟器 ABI 一致。

先检查设备和 ABI：

```bash
adb devices
adb shell getprop ro.product.cpu.abi
```

例如：

- `arm64-v8a` 对应 `frida-server-<版本>-android-arm64`
- `x86_64` 对应 `frida-server-<版本>-android-x86_64`

建议使用虚拟环境安装 Python 依赖：

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install frida-tools frida hpack
frida --version
```

从 Frida Releases 下载与 `frida --version` 完全一致、架构匹配的
`frida-server`，解压后保存在 Mac 当前目录。

## 3. 部署并启动 frida-server

推送并授权：

```bash
adb push frida-server /data/local/tmp/frida-server
adb shell "su -c 'chmod 755 /data/local/tmp/frida-server'"
```

每次模拟器重启后，都要重新启动 `frida-server`。这是抓取前的必要步骤：

```bash
adb shell "su -c '/data/local/tmp/frida-server &'"
```

如果已有旧进程或升级了 Frida 版本，先停止再启动：

```bash
adb shell "su -c 'pkill -f frida-server'"
adb shell "su -c '/data/local/tmp/frida-server &'"
```

验证连接：

```bash
frida-ps -U
frida-ps -Uai | grep -i corplink
```

`frida-ps -U` 能列出设备进程，才说明服务端版本、架构、Root 权限和连接都正常。

## 4. 清理会干扰 VPN 的旧设置

本方案不使用系统代理。先检查并删除遗留代理：

```bash
adb shell settings get global http_proxy
adb shell settings delete global http_proxy
```

如果之前配置过 iptables DNAT，只查看并精确删除自己添加的规则，不要直接清空
系统的整条链：

```bash
adb shell "su -c 'iptables -t nat -L OUTPUT -n -v --line-numbers'"
```

跨机器透明代理不可用于这里：DNAT 状态在 Android 上，而 Mac 上的 mitmproxy
无法通过 `SO_ORIGINAL_DST` 获取原目标地址，会持续报：

```text
Transparent mode failure: Could not resolve original destination.
```

此外，Android 同一时间通常只能运行一个 `VpnService`。因此 mitmproxy 的
WireGuard/VPN 模式会与 CorpLink 本身冲突。

## 5. 查找包名与进程

按应用名查包名：

```bash
frida-ps -Uai | grep -i corplink
```

CorpLink 的包名为：

```text
com.volcengine.corplink
```

查看所有相关运行进程：

```bash
frida-ps -U | grep -E 'com\.volcengine\.corplink($|:)'
```

常见进程包括：

- `com.volcengine.corplink`：主进程，登录和常规业务接口。
- `com.volcengine.corplink:channel`：长连接或通道相关流量。
- `com.volcengine.corplink:vpn`：VPN 建连、心跳和断开流量。

`/vpn/conn` 通常由 `:vpn` 进程发送。只附加主进程会漏掉它。

## 6. 推荐抓取流程

为避免把敏感抓取结果放进 Git 仓库，建议输出到权限受限的临时目录：

```bash
cd /Users/yanick/codes/mine/corplink-rs
CAPTURE_DIR="$(mktemp -d /private/tmp/corplink-httpdump.XXXXXX)"
chmod 700 "$CAPTURE_DIR"
python3 hack/httpdump.py com.volcengine.corplink "$CAPTURE_DIR/catch-it"
```

也可以在 `hack/` 目录直接运行：

```bash
cd hack
python3 httpdump.py com.volcengine.corplink catch-it
```

但这样会在仓库内生成包含敏感信息的文件，不推荐，也不要提交。

默认传包名时，脚本会：

1. 使用 Frida spawn 冷启动主进程。
2. 在主进程恢复执行前安装 hook，覆盖启动阶段的早期请求。
3. 每 0.3 秒轮询一次，自动补挂 `:channel`、`:vpn` 等子进程。
4. 同时解析 HTTP/1.1、HTTP/2，并保留原始 SSL 读写日志。

脚本启动后，在模拟器中完整执行：

1. 登录。
2. 等待初始化和节点列表加载完成。
3. 选择节点并连接 VPN。
4. 至少等待一次 `/vpn/report`。
5. 主动断开 VPN。
6. 回到终端按 `Ctrl+C`，让脚本完成导出。

不要用 `kill -9` 停止 Python 脚本，否则最终 JSON 可能来不及写入。

## 7. 输出文件

假设输出前缀为 `catch-it`，会生成：

| 文件 | 内容 |
|---|---|
| `catch-it.log` | HTTP/1.1、HTTP/2 的结构化流水，适合人工阅读 |
| `catch-it.json` | 按接口去重并过滤常见监控噪声后的 API 清单 |
| `catch-it.ndjson` | 每个已完成请求/响应一行 JSON，未去重 |
| `catch-it.raw.log` | 每次 `SSL_write`/`SSL_read` 的原始诊断输出 |

给文件收紧权限：

```bash
chmod 600 "$CAPTURE_DIR"/catch-it.*
```

列出结构化接口：

```bash
jq -r '.[] | [.proc, ("h" + .http), .method, (.host + .path), (.status | tostring)] | @tsv' \
  "$CAPTURE_DIR/catch-it.json"
```

检查 VPN 关键接口：

```bash
grep -nE '/vpn/(conn|report)' \
  "$CAPTURE_DIR/catch-it.log" \
  "$CAPTURE_DIR/catch-it.ndjson" \
  "$CAPTURE_DIR/catch-it.raw.log"
```

注意：

- `.json` 是去重后的 inventory，不等于完整时序。
- `.ndjson` 只记录已经成功完成结构化配对的请求。
- `.log` 为方便阅读会截断较长 body 的屏幕预览。
- `.raw.log` 是排查解析遗漏的兜底，但二进制块只保留有限长度的 hexdump 预览。
- 怀疑结构化解析漏包时，应同时检查 `.raw.log`。

## 8. attach 模式和单 PID 模式

抓已经运行的所有相关进程，不重启 App：

```bash
python3 hack/httpdump.py com.volcengine.corplink "$CAPTURE_DIR/catch-it" --attach
```

直接附加单个 PID：

```bash
python3 hack/httpdump.py <VPN进程PID> "$CAPTURE_DIR/catch-vpn"
```

单 PID 适用于以下情况：

- 自动轮询没有及时挂上 `:vpn`。
- 需要单独分析某个子进程。
- 希望在第二次连接前提前挂住常驻的 `:vpn` 进程。

先查 PID：

```bash
frida-ps -U | grep 'com.volcengine.corplink:vpn'
```

然后先启动脚本，再在 App 中重新触发一次连接。

默认 spawn 模式通常最完整。attach 到已经建立的 HTTP/2 长连接中途时，可能因为
缺少最初的 HPACK 动态表而无法解码已有连接的 HEADERS。遇到这种情况，应保持 hook
运行，并让 App 重新建立一条新的连接。

## 9. 常见问题

### `frida-ps -U` 无法连接

检查：

1. `frida-server` 是否在模拟器重启后重新启动。
2. Mac 与 Android 的 Frida 版本是否完全一致。
3. `frida-server` 架构是否匹配 ABI。
4. 是否通过 `su -c` 以 Root 权限运行。

### `ProcessNotFoundError`

attach 模式要求进程已经存在。优先直接传包名使用默认 spawn：

```bash
python3 hack/httpdump.py com.volcengine.corplink "$CAPTURE_DIR/catch-it"
```

### 没有 `/vpn/conn`

依次检查：

1. 是否真的执行了“连接 VPN”。
2. 日志是否出现已附加 `com.volcengine.corplink:vpn`。
3. `frida-ps -U` 是否能看到 `:vpn` 进程。
4. 保持脚本运行，断开后重新连接一次。
5. 必要时改用 `:vpn` PID 单独 attach。

### 只看到 `PRI * HTTP/2.0` 或 HTTP/2 Magic

这说明 TLS 明文已经抓到，但附加时间可能晚于首个 HEADERS，或者 HPACK 动态表不完整。
应在 hook 安装完成后重新建立 VPN 控制连接。不要仅靠 grep 在原始 HTTP/2 帧里找
`/vpn/conn`，因为 `:path` 可能经过 HPACK 压缩。

### `hpack decode error`

通常是中途附加导致缺少动态表。使用默认 spawn 模式冷启动，或在 attach 完成后让
目标进程重新建立 TLS/HTTP2 连接。

### `libssl.so` 或 `SSL_write` 找不到

当前脚本针对加载标准 `libssl.so` 并导出 `SSL_read`/`SSL_write` 的进程。若应用版本
改用静态链接 TLS、Go `crypto/tls` 或自研网络栈，需要另外定位相应明文入口。

当前验证过的 CorpLink 版本中：

- 主进程存在 HTTP/1.1 控制流。
- `:vpn` 进程存在基于 `libssl.so` 的 HTTP/2 控制流。

### Frida 17 报 `TypeError: not a function`

不要再使用旧式 API：

```javascript
Module.findExportByName(...)
Memory.readByteArray(ptr, len)
```

当前脚本已经使用 Frida 17 兼容写法：

```javascript
Process.getModuleByName("libssl.so").getExportByName(...)
ptr.readByteArray(len)
```

### tcpdump 文件快速膨胀

不要对 VPN App 长时间运行：

```text
tcpdump -i any -s 0 ...
```

`any` 可能同时记录物理接口和 TUN 接口上的同一批流量；VPN 建立后还会包含整个隧道
的数据面流量，文件会快速增长。此前几十 GB 的 pcap 就是由此产生。

本指南的 Frida 方案直接保存控制流明文，不需要全量 tcpdump。

## 10. tcpdump 仅作辅助

tcpdump 适合确认目标 IP、端口和 TLS 握手，不负责直接还原 HTTPS 明文。端口号也不
等同于协议：服务端可以在 80 端口上运行 TLS，不能仅凭端口判断 HTTP/HTTPS。

如果确实需要 pcap：

1. 只抓真实出口接口，例如 `eth0`，不要用 `any`。
2. 使用 BPF 限制目标 IP/端口。
3. 使用循环文件限制总大小。
4. 抓取前后都检查设备磁盘空间。

示例：

```bash
adb shell "su -c 'tcpdump -i eth0 -s 0 -C 50 -W 3 -w /sdcard/control.pcap \"(port 80 or port 443)\"'"
```

结束时优先发送正常中断，让 tcpdump 刷新 pcap：

```bash
adb shell "su -c 'pkill -INT -f tcpdump'"
adb pull /sdcard/control.pcap .
```

不同 tcpdump 版本使用 `-C/-W` 时可能生成带数字后缀的多个文件，拉取前先用
`adb shell ls -lh /sdcard/control.pcap*` 确认。

## 11. 安全与清理

四种输出都可能包含：

- `Authorization`、Cookie、CSRF、JWT 或 VPN token。
- OTP、设备标识和用户信息。
- VPN 公钥、节点地址、内部路由、DNS 和域名。
- 请求体与完整响应体。

因此：

1. 不要提交 `catch-it.*`、`*.pcap`、`keys.log` 等抓取产物。
2. 不要将原始日志直接粘贴到 Issue、PR 或公开聊天。
3. 分享前至少脱敏 `authorization`、`cookie`、`csrf-token`、`jwt-token`、
   `vpn-token`、`sign`、OTP、设备 ID、节点 IP 和内部域名。
4. 临时文件使用 `chmod 600`，完成分析后从明确的临时目录中删除。
5. 不再使用时停止 Frida：

```bash
adb shell "su -c 'pkill -f frida-server'"
```

`hack/` 目录和本指南用于本地调试，不随正式版本发布。
