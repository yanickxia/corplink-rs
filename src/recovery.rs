use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use reqwest::{Client, ClientBuilder, Proxy};

use crate::config::TunnelRecoveryConfig;
use crate::wg::UAPIClient;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryReason {
    TunnelUnavailable,
}

#[derive(Default)]
struct FailureWindow {
    count: u32,
    first: Option<Instant>,
    last: Option<Instant>,
}

impl FailureWindow {
    fn observe(&mut self, failed: bool, now: Instant, reset_gap: Duration) {
        if !failed {
            self.reset();
            return;
        }

        if self
            .last
            .is_some_and(|last| now.saturating_duration_since(last) > reset_gap)
        {
            self.reset();
        }
        self.first.get_or_insert(now);
        self.last = Some(now);
        self.count = self.count.saturating_add(1);
    }

    fn ready(&self, now: Instant, min_failures: u32, min_window: Duration) -> bool {
        self.count >= min_failures
            && self
                .first
                .is_some_and(|first| now.saturating_duration_since(first) >= min_window)
    }

    fn window(&self, now: Instant) -> Duration {
        self.first
            .map(|first| now.saturating_duration_since(first))
            .unwrap_or_default()
    }

    fn reset(&mut self) {
        *self = Self::default();
    }
}

#[derive(Default)]
struct AvailabilityDetector {
    handshake: FailureWindow,
    access: FailureWindow,
}

impl AvailabilityDetector {
    fn observe(
        &mut self,
        handshake_ok: bool,
        access_ok: bool,
        now: Instant,
        config: &TunnelRecoveryConfig,
    ) -> bool {
        let reset_gap = Duration::from_secs(config.reset_gap_secs.max(1));
        self.handshake.observe(!handshake_ok, now, reset_gap);
        self.access.observe(!access_ok, now, reset_gap);

        let min_window = Duration::from_secs(config.min_failure_window_secs);
        self.handshake
            .ready(now, config.min_failures.max(1), min_window)
            && self
                .access
                .ready(now, config.min_failures.max(1), min_window)
    }

    fn reset(&mut self) {
        *self = Self::default();
    }
}

pub struct RecoveryMonitor {
    config: TunnelRecoveryConfig,
    tunnel_client: Client,
    underlay_client: Client,
    underlay_probe_url: String,
    detector: AvailabilityDetector,
    started: bool,
}

impl RecoveryMonitor {
    pub fn new(
        config: TunnelRecoveryConfig,
        control_plane_url: &str,
        socks5_listen: Option<&str>,
        socks5_username: &str,
        socks5_password: &str,
    ) -> Result<Self> {
        let timeout = Duration::from_secs(config.probe_timeout_secs.max(1));
        let mut tunnel_builder = ClientBuilder::new()
            .timeout(timeout)
            .no_proxy()
            .user_agent("corplink-rs recovery probe");
        if let Some(listen) = socks5_listen {
            let proxy_url = format!("socks5h://{}", loopback_proxy_endpoint(listen));
            let mut proxy = Proxy::all(&proxy_url)
                .with_context(|| format!("invalid recovery SOCKS5 proxy {proxy_url}"))?;
            if !socks5_username.is_empty() {
                proxy = proxy.basic_auth(socks5_username, socks5_password);
            }
            tunnel_builder = tunnel_builder.proxy(proxy);
        }

        let tunnel_client = tunnel_builder
            .build()
            .context("failed to build tunnel recovery probe client")?;
        let underlay_client = ClientBuilder::new()
            .timeout(timeout)
            .no_proxy()
            .user_agent("corplink-rs underlay probe")
            .build()
            .context("failed to build underlay recovery probe client")?;
        let underlay_probe_url = config
            .underlay_probe_url
            .clone()
            .unwrap_or_else(|| control_plane_url.to_string());

        Ok(Self {
            config,
            tunnel_client,
            underlay_client,
            underlay_probe_url,
            detector: AvailabilityDetector::default(),
            started: false,
        })
    }

    pub fn config(&self) -> &TunnelRecoveryConfig {
        &self.config
    }

    pub fn reset(&mut self) {
        self.detector.reset();
    }

    pub async fn wait_until_unhealthy(&mut self, uapi: &UAPIClient) -> RecoveryReason {
        if !self.started {
            self.started = true;
            tokio::time::sleep(Duration::from_secs(self.config.initial_delay_secs)).await;
        }

        loop {
            let (handshake_ok, access_ok) = self.probe_tunnel(uapi).await;
            let now = Instant::now();

            if !handshake_ok && !access_ok {
                let underlay_ok =
                    http_reachable(&self.underlay_client, &self.underlay_probe_url, "underlay")
                        .await;
                if !underlay_ok {
                    log::warn!(
                        "recovery probe: tunnel unavailable but control-plane underlay is down; preserving tunnel"
                    );
                    self.detector.reset();
                } else if self
                    .detector
                    .observe(handshake_ok, access_ok, now, &self.config)
                {
                    log::warn!(
                        "recovery: accepted availability request (handshake failures={}, access failures={}, windows={}s/{}s)",
                        self.detector.handshake.count,
                        self.detector.access.count,
                        self.detector.handshake.window(now).as_secs(),
                        self.detector.access.window(now).as_secs(),
                    );
                    return RecoveryReason::TunnelUnavailable;
                }
            } else {
                self.detector
                    .observe(handshake_ok, access_ok, now, &self.config);
            }

            tokio::time::sleep(Duration::from_secs(self.config.probe_interval_secs.max(1))).await;
        }
    }

    pub async fn validate_transport(&self, uapi: &UAPIClient) -> bool {
        let deadline =
            Instant::now() + Duration::from_secs(self.config.repair_validation_secs.max(1));
        loop {
            let (handshake_ok, access_ok) = self.probe_tunnel(uapi).await;
            if access_ok {
                log::info!(
                    "recovery: transport repair validated (handshake_ok={handshake_ok}, access_ok=true)"
                );
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_secs(self.config.probe_interval_secs.max(1))).await;
        }
    }

    async fn probe_tunnel(&self, uapi: &UAPIClient) -> (bool, bool) {
        let handshake_stale = Duration::from_secs(self.config.handshake_stale_secs.max(1));
        let (handshake, access_ok) = tokio::join!(
            uapi.latest_handshake_age(),
            http_reachable(
                &self.tunnel_client,
                &self.config.tunnel_probe_url,
                "tunnel access",
            )
        );
        let handshake_ok = match handshake {
            Ok(Some(age)) => {
                log::debug!("recovery probe: latest handshake age={}s", age.as_secs());
                age <= handshake_stale
            }
            Ok(None) => false,
            Err(err) => {
                log::warn!("recovery probe: failed to read WireGuard handshake: {err:#}");
                false
            }
        };
        log::debug!("recovery probe: handshake_ok={handshake_ok} access_ok={access_ok}");
        (handshake_ok, access_ok)
    }
}

async fn http_reachable(client: &Client, url: &str, label: &str) -> bool {
    match client.get(url).send().await {
        Ok(response) => {
            log::debug!(
                "recovery probe: {label} reachable, status={}",
                response.status()
            );
            true
        }
        Err(err) => {
            log::warn!("recovery probe: {label} failed: {err}");
            false
        }
    }
}

fn loopback_proxy_endpoint(listen: &str) -> String {
    match listen.parse::<SocketAddr>() {
        Ok(addr) if addr.ip().is_unspecified() => {
            let ip = match addr.ip() {
                IpAddr::V4(_) => IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            };
            SocketAddr::new(ip, addr.port()).to_string()
        }
        _ => listen.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    fn test_config() -> TunnelRecoveryConfig {
        serde_json::from_value(serde_json::json!({})).unwrap()
    }

    #[test]
    fn detector_requires_both_signals_and_full_window() {
        let mut detector = AvailabilityDetector::default();
        let mut config = test_config();
        config.min_failures = 3;
        config.min_failure_window_secs = 30;
        let start = Instant::now();

        assert!(!detector.observe(false, false, start, &config));
        assert!(!detector.observe(false, false, start + Duration::from_secs(15), &config));
        assert!(detector.observe(false, false, start + Duration::from_secs(30), &config));

        detector.reset();
        assert!(!detector.observe(true, false, start, &config));
        assert!(!detector.observe(true, false, start + Duration::from_secs(30), &config));
    }

    #[test]
    fn detector_resets_after_observation_gap() {
        let mut detector = AvailabilityDetector::default();
        let mut config = test_config();
        config.min_failures = 2;
        config.min_failure_window_secs = 1;
        config.reset_gap_secs = 90;
        let start = Instant::now();

        assert!(!detector.observe(false, false, start, &config));
        assert!(!detector.observe(false, false, start + Duration::from_secs(91), &config));
        assert_eq!(detector.handshake.count, 1);
        assert_eq!(detector.access.count, 1);
    }

    #[test]
    fn wildcard_socks_listener_is_probed_through_loopback() {
        assert_eq!(loopback_proxy_endpoint("0.0.0.0:1080"), "127.0.0.1:1080");
        assert_eq!(loopback_proxy_endpoint("127.0.0.1:1080"), "127.0.0.1:1080");
        assert_eq!(loopback_proxy_endpoint("[::]:1080"), "[::1]:1080");
    }

    #[tokio::test]
    async fn netstack_probe_uses_socks_remote_dns() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = listener.local_addr().unwrap();
        let (domain_tx, domain_rx) = oneshot::channel();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let mut greeting = [0_u8; 2];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting[0], 5);
            let mut methods = vec![0_u8; greeting[1] as usize];
            stream.read_exact(&mut methods).await.unwrap();
            assert!(methods.contains(&0));
            stream.write_all(&[5, 0]).await.unwrap();

            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [5, 1, 0, 3]);
            let domain_len = stream.read_u8().await.unwrap() as usize;
            let mut domain = vec![0_u8; domain_len];
            stream.read_exact(&mut domain).await.unwrap();
            let mut port = [0_u8; 2];
            stream.read_exact(&mut port).await.unwrap();
            domain_tx.send(String::from_utf8(domain).unwrap()).unwrap();

            stream
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
            let mut request_bytes = Vec::new();
            loop {
                let byte = stream.read_u8().await.unwrap();
                request_bytes.push(byte);
                if request_bytes.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });

        let mut config = test_config();
        config.tunnel_probe_url = "http://probe.internal/health".to_string();
        config.probe_timeout_secs = 2;
        let monitor = RecoveryMonitor::new(
            config,
            "http://127.0.0.1/",
            Some(&listen.to_string()),
            "",
            "",
        )
        .unwrap();

        assert!(
            http_reachable(
                &monitor.tunnel_client,
                &monitor.config.tunnel_probe_url,
                "test tunnel",
            )
            .await
        );
        assert_eq!(domain_rx.await.unwrap(), "probe.internal");
    }
}
