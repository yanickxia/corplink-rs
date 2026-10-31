# Corplink for ImmortalWrt

原生 LuCI 页面，入口为 **服务 → Corplink**。支持网页设备登录、回调地址和 MFA 验证码提交、代理配置、运行状态、脱敏日志、服务启停和开机自启。

当前构建目标是 **ImmortalWrt 25.12 / x86_64 / APK**，由两个软件包组成：

- `corplink-rs-dev`：基于 dev 的核心，增加只登录接口；包含 procd 服务和 Go rpcd 后台。
- `luci-app-corplink-rs`：LuCI JS 页面、菜单和权限定义。

本版本使用纯代理模式，默认监听 `127.0.0.1:1188`，不添加系统路由，不修改系统 DNS。设备配置沿用 `corplink-n5100` 名称。软件包不包含任何企业账号、设备 ID、Cookie 或密钥。

## 使用

登录路由器 LuCI，打开 **服务 → Corplink**。已保存的配置和会话会直接显示，无需重新认证。

首次使用或重新认证：

1. 停止代理服务，填写并保存企业、服务地址、官方已注册的设备 ID 和设备名称。
2. 点击「开始登录」，打开授权页面。
3. 浏览器提示打开飞连时可取消，复制地址栏完整回调地址，回到 LuCI 提交。
4. 按页面提示提交邮箱或动态验证码。
5. 显示登录成功后点击「启动」。需要开机启动时单独点击「启用开机自启」。

使用独立注册的设备身份，避免与其他客户端共用设备造成会话互踢。设备 ID 必须完整复制，不随机生成。修改企业、账号或设备字段后需要重新登录；只改节点或代理端口会保留会话。

命令行仍可使用：

```sh
service corplink-rs-dev start
service corplink-rs-dev stop
service corplink-rs-dev restart
service corplink-rs-dev status
service corplink-rs-dev enable
service corplink-rs-dev disable
service corplink-rs-dev check
service corplink-rs-dev login
```

`login` 需要交互终端，只完成认证；认证后不会自动连接。也可直接使用核心的 `--login-only config.json`。`--login-json config.json` 是供后台使用的逐行 JSON 事件接口，不应手工将输出中的授权 URL 或输入凭据发布到日志中。

## 安装

上传两个 APK 后，在路由器执行：

```sh
apk add --allow-untrusted --no-network \
  ./corplink-rs-dev-6.6.0-r2.apk \
  ./luci-app-corplink-rs-1.0.0-r2.apk
```

这里的 `--allow-untrusted` 只用于本地生成的未签名软件包，不修改路由器的全局信任设置。安装前需要已有 `ca-bundle`、`jsonfilter`、`rpcd`、`luci-base`。这不是面向旧版 opkg 的 IPK。

安装和升级前会备份旧核心及 init 脚本到 `/usr/share/corplink-rs-dev/backup-package-*`；安装脚本保留现有连接、配置、登录会话和自启选择，不主动启动或重启 VPN。插件安装后刷新 rpcd 和 LuCI 缓存，重新打开网页即可。

卸载核心会停止服务；配置和会话备份保留在 `/etc/corplink-rs-dev/`。如要恢复旧核心，先停止服务，从对应 `backup-package-*` 复制回核心和 init 脚本，再按需启动。

## 构建

要求 Python 3.12+、Docker、Rust/Cargo、Go。Go manager 不依赖第三方模块。构建不会覆盖工作区或已安装二进制，已有输出二进制会另存备份。

```sh
git submodule update --init --recursive

# 在有足够资源的 Linux/amd64 Docker 主机上构建；也可指定远程 Docker。
export DOCKER_HOST=ssh://n5100
python3 openwrt/scripts/build-core.py \
  --work-dir /Users/yanick/software/corplink/luci-build

# APK 打包需要本机 Docker 可访问输出目录，不能使用远程 bind mount。
unset DOCKER_HOST
python3 openwrt/scripts/build-apk.py \
  --binaries /Users/yanick/software/corplink/luci-build/out \
  --output /Users/yanick/software/corplink/luci-packages
```

可用 `--wireguard-source` 指定另一个已有子模块仓库；脚本仍归档当前分支锁定的提交，而非其工作区。`--offline` 只使用 Cargo 本地缓存。

构建固定 Rust 1.96.0、Go 1.25.5 以及 WireGuard 提交 `a73b9f07989a647ad7f4d84184efb3b1b8ea77a4`。Rust 使用 release、locked 依赖及 vendor 目录；libwg 从固定提交重新编译，执行 Go 和 Rust 回归测试。Linux/amd64 musl 适配器位于 `build/`，与固定 Go 的 c-archive 构造函数配套，升级工具链时需要复核。

`out/BUILD-INFO.json` 记录源码指纹、基础提交、构建工具、二进制 SHA256 与构建检查；APK 目录另有 `SHA256SUMS`。新增只登录接口的产物应标识为 **dev + LuCI 修改**，不是未修改的 dev。

也提供 SDK 配方。将完整 `openwrt/` 放到 SDK 的 `package/corplink/`，准备 LuCI feed，并设置 `CORPLINK_PREBUILT_DIR` 为与目标架构匹配的构建输出目录；`LUCI_MK` 可覆盖 LuCI include 路径。SDK 配方安装 init 模板时避开 SDK 的自动启动钩子。当前实机验证使用上面的 APK 打包脚本；SDK 配方及其他架构尚未完成构建验证。

## 验证

```sh
(cd openwrt/manager && go test -race ./...)

PLAYWRIGHT_MODULE=/path/to/playwright \
CHROME_BIN=/path/to/chrome node openwrt/tests/ui.cjs

# 在路由器使用临时新核心测试，只访问本地假网关，不发起真实登录或 VPN。
python3 openwrt/tests/login-cli.py --ssh n5100 --binary /tmp/corplink-luci-test

# 安装后只读检查真实页面，并创建、销毁短期 LuCI 测试会话。
PLAYWRIGHT_MODULE=/path/to/playwright \
CHROME_BIN=/path/to/chrome node openwrt/tests/router-ui.cjs
```

后台测试覆盖会话备份、身份变更、运行中操作拒绝、MFA、取消、失败、旧步骤重放、配置并发修改和日志脱敏。UI 测试覆盖输入保留、重复提交和移动端布局。实机页面测试不会操作当前 VPN 的启停按钮。

## 配置和认证边界

- `/etc/corplink-rs-dev/` 仅 root 可访问；配置、Cookie、认证备份权限为 600。
- 登录在 `/var/run/corplink-rs-dev/auth-<id>/` 的临时目录进行，10 分钟超时；取消或失败保留旧会话，成功后校验配置未变化再替换。
- RPC 只接受固定配置字段和服务操作；LuCI ACL 分离只读及写入权限，没有任意文件读取或命令执行入口。
- Cookie、OTP 秘钥、私钥和提交的授权结果不会作为状态或配置返回给页面。日志经过脱敏；授权 URL 仅在当前登录过程中显示。
- LuCI 显示「已保存」表示有本地会话；是否仍被服务端接受，需要实际连接确认。登录本身不请求 VPN 节点、不创建隧道。
- 本机 SOCKS5 仅供路由器上的程序使用；可通过 SSH 端口转发从自己的电脑访问。
