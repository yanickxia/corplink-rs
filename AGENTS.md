# 本地构建约定

- 本地编译完成后的可执行文件统一安装到 `/Users/yanick/software/corplink/`。
- 原版使用 `master` 分支，文件名为 `corplink-rs`。
- 我们的改版使用 `dev` 分支，文件名为 `corplink-rs-dev`。
- 使用 release 构建和锁定依赖（`cargo build --release --locked`），并使用对应分支锁定的 WireGuard 子模块版本重新构建 `libwg`，避免原版与改版混用底层库。
- 覆盖已有可执行文件前保留备份。仅构建、安装时，不主动启动或重启 VPN 服务。

# 上游维护原则

- JWT 与请求签名以 `upstream/master` 的实现为准，优先复用上游代码和回归测试，减少独立维护的重复实现。
- 对比 `dev` 与 `master` 时，以当前仍生效的功能差异为准；历史提交中已被上游覆盖或被后续提交移除的方案，不算作需要保留的扩展。
