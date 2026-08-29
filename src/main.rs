mod api;
mod client;
mod config;
mod dns;
mod qrcode;
mod recovery;
mod resp;
mod sign;
mod state;
mod template;
mod totp;
mod utils;
mod wg;

#[cfg(windows)]
use is_elevated;

#[cfg(any(target_os = "macos", target_os = "linux"))]
use dns::DNSManager;

use std::env;
use std::process::{exit, Command};
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::process::CommandExt;

use anyhow::{anyhow, Context, Result};

use client::Client;
use config::{Config, WgConf};
use recovery::RecoveryMonitor;

const RECOVERY_REBUILD_NOT_BEFORE_ENV: &str = "CORPLINK_RECOVERY_REBUILD_NOT_BEFORE";

fn print_usage_and_exit(name: &str, conf: &str) {
    println!("usage:\n\t{} {}", name, conf);
    exit(1);
}

fn parse_arg() -> String {
    let mut conf_file = String::from("config.json");
    let mut args = env::args();
    // pop name
    let name = args.next().unwrap();
    match args.len() {
        0 => {}
        1 => {
            // pop arg
            let arg = args.next().unwrap();
            match arg.as_str() {
                "-h" | "--help" => {
                    print_usage_and_exit(&name, &conf_file);
                }
                _ => {
                    conf_file = arg;
                }
            }
        }
        _ => {
            print_usage_and_exit(&name, &conf_file);
        }
    }
    conf_file
}

pub const EPERM: i32 = 1;
pub const ENOENT: i32 = 2;
pub const ETIMEDOUT: i32 = 110;

enum TunnelAction {
    Exit(i32),
    Restart { cooldown_secs: u64 },
}

async fn wait_for_tunnel_exit<S, W>(shutdown: S, handshake: W) -> i32
where
    S: std::future::Future<Output = ()>,
    W: std::future::Future<Output = ()>,
{
    tokio::select! {
        _ = shutdown => 0,
        _ = handshake => ETIMEDOUT,
    }
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        log::error!("{:#}", err);
        exit(EPERM);
    }
}

async fn run() -> Result<()> {
    // NOTE: If you want to debug, you should set `RUST_LOG` env to `debug` and run corplink-rs in root
    //  because `check_privilege` will call sudo and drop env if you're not root
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    print_version();

    let conf_file = parse_arg();
    let mut conf = Config::from_file(&conf_file)
        .await
        .context("failed to load config")?;
    let name = conf
        .interface_name
        .clone()
        .context("interface name missing in config")?;
    let socks5_listen = conf.socks5_listen.clone();
    let socks5_username = conf.socks5_username.clone().unwrap_or_default();
    let socks5_password = conf.socks5_password.clone().unwrap_or_default();
    let netstack_mode = socks5_listen.is_some();

    // netstack/socks5 mode runs entirely in userspace (no kernel TUN device,
    // no system routes/dns), so it does not require elevated privileges.
    if !netstack_mode {
        check_privilege();
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let use_vpn_dns = conf.use_vpn_dns.unwrap_or(false);
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let dns_backup_filename = conf.dns_backup_filename.clone();

    if conf.server.is_none() {
        let resp = client::get_company_url(conf.company_name.as_str())
            .await
            .with_context(|| {
                format!(
                    "failed to fetch company server from company name {}",
                    conf.company_name
                )
            })?;
        log::info!(
            "company name is {}(zh)/{}(en) server is {}",
            resp.zh_name,
            resp.en_name,
            resp.domain
        );
        conf.server = Some(resp.domain);
        conf.save()
            .await
            .context("failed to persist company server")?;
    }

    let with_wg_log = conf.debug_wg.unwrap_or_default();
    let platform = conf.platform.clone();
    let recovery_config = conf
        .tunnel_recovery
        .clone()
        .filter(|recovery| recovery.enabled);
    let control_plane_url = conf
        .server
        .clone()
        .context("server url missing after company discovery")?;
    let mut c = Client::new(conf).context("failed to initialize client")?;
    let mut logout_retry = true;
    let wg_conf: Option<WgConf>;

    loop {
        if c.need_login() {
            log::info!("not login yet, try to login");
            c.login().await.context("login failed")?;
            log::info!("login success");
        }
        log::info!("try to connect");
        match c.connect_vpn().await {
            Ok(conf) => {
                wg_conf = Some(conf);
                break;
            }
            Err(e) => {
                if logout_retry && e.to_string().contains("logout") {
                    // e contains detail message, so just print it out
                    log::warn!("{}", e);
                    logout_retry = false;
                    continue;
                } else {
                    return Err(e);
                }
            }
        };
    }
    let wg_conf = wg_conf.ok_or_else(|| anyhow!("wg conf missing after connect loop"))?;
    let protocol = wg_conf.protocol;
    let mut uapi = wg::UAPIClient { name: name.clone() };
    if let Some(listen) = &socks5_listen {
        log::info!("start wg-corplink (netstack/socks5) on {}", listen);
        wg::start_wg_go_netstack(
            &wg_conf,
            listen,
            &socks5_username,
            &socks5_password,
            with_wg_log,
        )
        .context("failed to start wg-corplink in netstack mode")?;
        uapi.config_wg_netstack(&wg_conf)
            .await
            .context("failed to config netstack interface with uapi")?;
        if socks5_username.is_empty() {
            log::info!("socks5 proxy ready at {} (no auth)", listen);
        } else {
            log::info!(
                "socks5 proxy ready at {} (username/password auth required)",
                listen
            );
        }
    } else {
        log::info!("start wg-corplink for {}", &name);
        wg::start_wg_go(&name, protocol, with_wg_log)
            .with_context(|| format!("failed to start wg-corplink for {}", name))?;
        uapi.config_wg(&wg_conf)
            .await
            .with_context(|| format!("failed to config interface with uapi for {name}"))?;
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let mut dns_manager = DNSManager::new(dns_backup_filename);

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if use_vpn_dns && !netstack_mode {
        match dns_manager.set_dns(vec![&wg_conf.dns], vec![]) {
            Ok(_) => {}
            Err(err) => {
                log::warn!("failed to set dns: {}", err);
            }
        }
    }

    let shutdown = wait_for_shutdown_signal();
    tokio::pin!(shutdown);

    // `/vpn/report` is control-plane telemetry, not tunnel liveness. In stable
    // mode keep the 6.5.2 behavior. The preview recovery block adds an active
    // access probe plus handshake freshness, underlay discrimination, a bind
    // repair attempt and finally a process-level full rebuild.
    let action = if let Some(recovery_config) = recovery_config {
        log::info!(
            "tunnel recovery enabled: probe={} underlay={} interval={}s",
            recovery_config.tunnel_probe_url,
            recovery_config
                .underlay_probe_url
                .as_deref()
                .unwrap_or(&control_plane_url),
            recovery_config.probe_interval_secs.max(1),
        );
        let mut monitor = RecoveryMonitor::new(
            recovery_config,
            &control_plane_url,
            socks5_listen.as_deref(),
            &socks5_username,
            &socks5_password,
        )?;

        loop {
            let reason = tokio::select! {
                _ = &mut shutdown => break TunnelAction::Exit(0),
                reason = monitor.wait_until_unhealthy(&uapi) => reason,
            };
            log::warn!("recovery: event=availability action=accepted reason={reason:?}");

            let repair_delay = Duration::from_secs(monitor.config().repair_delay_secs);
            if !repair_delay.is_zero() {
                tokio::select! {
                    _ = &mut shutdown => break TunnelAction::Exit(0),
                    _ = tokio::time::sleep(repair_delay) => {}
                }
            }

            log::warn!("recovery: event=transport_repair action=start");
            let repair_timeout = Duration::from_secs(monitor.config().repair_timeout_secs.max(1));
            let repair_uapi = uapi.clone();
            let repair_conf = wg_conf.clone();
            let repair_task = tokio::task::spawn_blocking(move || {
                repair_uapi.repair_transport(&repair_conf)
            });
            let repaired = match tokio::time::timeout(repair_timeout, repair_task).await {
                Ok(Ok(Ok(()))) => {
                    log::info!("recovery: event=transport_repair action=rebound");
                    tokio::select! {
                        _ = &mut shutdown => break TunnelAction::Exit(0),
                        validated = monitor.validate_transport(&uapi) => validated,
                    }
                }
                Ok(Ok(Err(err))) => {
                    log::warn!("recovery: event=transport_repair action=failed error={err:#}");
                    false
                }
                Ok(Err(err)) => {
                    log::warn!("recovery: event=transport_repair action=join_failed error={err}");
                    false
                }
                Err(_) => {
                    log::warn!("recovery: event=transport_repair action=timeout");
                    false
                }
            };
            if repaired {
                log::info!("recovery: event=transport_repair action=success");
                monitor.reset();
                continue;
            }

            let now = chrono::Utc::now().timestamp();
            if let Some(not_before) = recovery_rebuild_not_before() {
                if now < not_before {
                    log::warn!(
                        "recovery: event=rebuild_budget action=deny retry_after={}s",
                        not_before - now
                    );
                    monitor.reset();
                    continue;
                }
            }
            let cooldown_secs = monitor.config().rebuild_cooldown_secs.max(1);
            log::warn!(
                "recovery: event=rebuild_budget action=admit next_allowed={}s",
                cooldown_secs
            );
            break TunnelAction::Restart { cooldown_secs };
        }
    } else {
        let exit_code = wait_for_tunnel_exit(&mut shutdown, async {
            uapi.check_wg_connection().await;
            log::warn!("last handshake timeout");
        })
        .await;
        TunnelAction::Exit(exit_code)
    };

    // shutdown
    if matches!(action, TunnelAction::Exit(_)) {
        log::info!("disconnecting vpn...");
        if let Err(e) = c.disconnect_vpn(&wg_conf).await {
            log::warn!("failed to disconnect vpn: {}", e)
        };

        // only logout for feilian_v1
        if platform.as_deref() == Some(config::PLATFORM_CORPLINK_V1) {
            log::info!("logging out current terminal...");
            if let Err(e) = c.logout().await {
                log::warn!("failed to logout: {}", e)
            };
        }
    } else {
        // A rebuild deliberately keeps the control-plane session/cookies and
        // public key. The replacement process immediately requests a fresh
        // peer configuration, matching the community recovery lifecycle more
        // closely than an explicit disconnect/logout.
        log::warn!("recovery: event=full_rebuild action=cleanup");
    }

    wg::stop_wg_go();

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if use_vpn_dns && !netstack_mode {
        match dns_manager.restore_dns() {
            Ok(_) => {}
            Err(err) => {
                log::warn!("failed to delete dns: {}", err);
            }
        }
    }

    match action {
        TunnelAction::Exit(exit_code) => {
            log::info!("reach exit");
            exit(exit_code)
        }
        TunnelAction::Restart { cooldown_secs } => {
            log::warn!("recovery: event=full_rebuild action=exec");
            restart_current_process(&conf_file, cooldown_secs)
        }
    }
}

fn recovery_rebuild_not_before() -> Option<i64> {
    env::var(RECOVERY_REBUILD_NOT_BEFORE_ENV)
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
}

fn restart_current_process(conf_file: &str, cooldown_secs: u64) -> Result<()> {
    let executable = env::current_exe().context("failed to locate current executable")?;
    let not_before = chrono::Utc::now()
        .timestamp()
        .saturating_add(cooldown_secs.min(i64::MAX as u64) as i64);
    let mut command = Command::new(executable);
    command
        .arg(conf_file)
        .env(RECOVERY_REBUILD_NOT_BEFORE_ENV, not_before.to_string());

    #[cfg(unix)]
    {
        let err = command.exec();
        Err(err).context("failed to exec replacement corplink-rs process")
    }

    #[cfg(windows)]
    {
        command
            .spawn()
            .context("failed to spawn replacement corplink-rs process")?;
        exit(0)
    }
}

// Resolve when the process is asked to terminate: ctrl+c (SIGINT) or, on unix,
// SIGTERM (sent by `docker stop`, systemd, `kill`, etc). Handling SIGTERM lets
// the graceful shutdown path run — notably the feilian_v1 logout that releases
// the server-side terminal slot, which is otherwise leaked on every stop.
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => Some(s),
            Err(e) => {
                log::warn!("failed to install SIGTERM handler: {}", e);
                None
            }
        };
        tokio::select! {
            r = tokio::signal::ctrl_c() => {
                if let Err(e) = r {
                    log::warn!("failed to receive signal: {}", e);
                }
                log::info!("ctrl+c received");
            }
            _ = async {
                match term.as_mut() {
                    Some(t) => { t.recv().await; }
                    None => std::future::pending::<()>().await,
                }
            } => {
                log::info!("SIGTERM received");
            }
        }
    }
    #[cfg(not(unix))]
    {
        if let Err(e) = tokio::signal::ctrl_c().await {
            log::warn!("failed to receive signal: {}", e);
        }
        log::info!("ctrl+c received");
    }
}

fn check_privilege() {
    #[cfg(unix)]
    match sudo::escalate_if_needed() {
        Ok(_) => {}
        Err(_) => {
            log::error!("please run as root");
            exit(EPERM);
        }
    }

    #[cfg(windows)]
    if !is_elevated::is_elevated() {
        log::error!("please run as administrator");
        exit(EPERM);
    }
}

fn print_version() {
    let pkg_name = env!("CARGO_PKG_NAME");
    let pkg_version = env!("CARGO_PKG_VERSION");
    log::info!("running {}@{}", pkg_name, pkg_version);
}

#[cfg(test)]
mod tests {
    use std::future::{pending, ready};

    use super::{wait_for_tunnel_exit, ETIMEDOUT};

    #[tokio::test]
    async fn shutdown_completion_exits_cleanly() {
        let exit_code = wait_for_tunnel_exit(ready(()), pending()).await;

        assert_eq!(exit_code, 0);
    }

    #[tokio::test]
    async fn handshake_completion_requests_tunnel_restart() {
        let exit_code = wait_for_tunnel_exit(pending(), ready(())).await;

        assert_eq!(exit_code, ETIMEDOUT);
    }
}
