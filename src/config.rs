use std::fmt;
use tokio::fs;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::state::State;
use crate::utils;

const DEFAULT_DEVICE_NAME: &str = "DollarOS";
const DEFAULT_INTERFACE_NAME: &str = "corplink";
pub(crate) const CORPLINK_ANDROID_APP_VERSION: &str = "3.3.16";

const DEFAULT_ANDROID_BUILD_NUMBER: &str = "2279";
const DEFAULT_ANDROID_BRAND: &str = "Android";
const DEFAULT_ANDROID_MODEL: &str = "Android SDK built for arm64";
const DEFAULT_ANDROID_RELEASE: &str = "8.1.0";
const DEFAULT_ANDROID_SDK: &str = "27";
const DEFAULT_ANDROID_PATCH: &str = "2018-01-05";
const DEFAULT_ANDROID_LANGUAGE: &str = "en";
const DEFAULT_ANDROID_CLIENT_SOURCE: &str = "FeiLian";
const DEFAULT_ANDROID_USER_AGENT: &str =
    "CorpLink/3.3.16 (AndroidAndroid SDK built for arm64; Android 8.1.0; en)";

pub const PLATFORM_LDAP: &str = "ldap";
pub const PLATFORM_CORPLINK: &str = "feilian";
// new feilian login that uses the v1 API (/api/v1/login with an AES-encrypted
// password), as served by the newer feilian backend. opt-in via config.
pub const PLATFORM_CORPLINK_V1: &str = "feilian_v1";
pub const PLATFORM_OIDC: &str = "OIDC";
// aka feishu
pub const PLATFORM_LARK: &str = "lark";
#[allow(dead_code)]
pub const PLATFORM_WEIXIN: &str = "weixin";
// aka dingding
#[allow(dead_code)]
pub const PLATFORM_DING_TALK: &str = "dingtalk";
// unknown
#[allow(dead_code)]
pub const PLATFORM_AAD: &str = "aad";

pub const STRATEGY_LATENCY: &str = "latency";
pub const STRATEGY_DEFAULT: &str = "default";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum RouteMode {
    /// Only intranet routes returned by the server (mimics official split mode).
    #[default]
    Split,
    /// Full-tunnel routes from the server (typically 0.0.0.0/0, ::/0).
    Full,
}

impl fmt::Display for RouteMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RouteMode::Split => write!(f, "split"),
            RouteMode::Full => write!(f, "full"),
        }
    }
}

/// Android client identity sent to CorpLink.
///
/// CorpLink Web persists the corresponding values as top-level fields.  The
/// Rust client keeps them grouped so changing the HTTP identity cannot
/// accidentally replace the stable top-level `device_id`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct AndroidProfile {
    pub app_version: String,
    pub build_number: String,
    pub brand: String,
    pub model: String,
    pub android_release: String,
    pub os_version: String,
    pub os_version_patch: String,
    pub language: String,
    pub client_source: String,
}

impl Default for AndroidProfile {
    fn default() -> Self {
        Self {
            app_version: CORPLINK_ANDROID_APP_VERSION.to_string(),
            build_number: DEFAULT_ANDROID_BUILD_NUMBER.to_string(),
            brand: DEFAULT_ANDROID_BRAND.to_string(),
            model: DEFAULT_ANDROID_MODEL.to_string(),
            android_release: DEFAULT_ANDROID_RELEASE.to_string(),
            os_version: DEFAULT_ANDROID_SDK.to_string(),
            os_version_patch: DEFAULT_ANDROID_PATCH.to_string(),
            language: DEFAULT_ANDROID_LANGUAGE.to_string(),
            client_source: DEFAULT_ANDROID_CLIENT_SOURCE.to_string(),
        }
    }
}

impl AndroidProfile {
    pub fn user_agent(&self) -> String {
        // The Android client concatenates brand and model directly. Its current
        // emulator identity is `AndroidAndroid SDK built for arm64`, without an
        // extra separator, while the query string still carries them separately.
        format!(
            "CorpLink/{} ({}{}; Android {}; {})",
            self.app_version, self.brand, self.model, self.android_release, self.language
        )
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Config {
    pub company_name: String,
    pub username: String,
    pub password: Option<String>,
    pub platform: Option<String>,
    pub code: Option<String>,
    pub device_name: Option<String>,
    pub device_id: Option<String>,
    /// Optional Android HTTP identity. This does not alter `device_id`,
    /// `device_name`, cookies, or WireGuard keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub android_profile: Option<AndroidProfile>,
    pub public_key: Option<String>,
    pub private_key: Option<String>,
    pub server: Option<String>,
    pub interface_name: Option<String>,
    pub debug_wg: Option<bool>,
    #[serde(skip_serializing)]
    pub conf_file: Option<String>,
    pub state: Option<State>,
    pub vpn_server_name: Option<String>,
    pub vpn_select_strategy: Option<String>,
    pub use_vpn_dns: Option<bool>,
    pub dns_backup_filename: Option<String>,
    pub auto_setup_routes: Option<bool>,
    /// "split" (default) or "full". Selects which route list from the server to apply.
    pub route_mode: Option<RouteMode>,
    /// Optional CIDRs added to the server-provided routes before route filters.
    /// Unlike `vpn_allowed_routes`, this expands the route set. The combined routes
    /// are then restricted by `vpn_allowed_routes` and `vpn_disallowed_routes`.
    pub vpn_additional_routes: Option<Vec<String>>,
    /// Optional hostnames resolved on every connection. Resolved addresses are appended
    /// as host routes before route filters.
    pub vpn_additional_domains: Option<Vec<String>>,
    /// Optional CIDR whitelist intersected with the server and additional routes.
    /// Missing/null preserves the combined routes; an empty list allows no routes.
    pub vpn_allowed_routes: Option<Vec<String>>,
    /// Optional list of CIDR routes to exclude from AllowedIPs / system routes.
    /// Useful in full mode to punch holes for local LAN or the VPN peer IP itself,
    /// avoiding routing loops (e.g. 192.168.1.0/24, 10.0.0.5/32).
    pub vpn_disallowed_routes: Option<Vec<String>>,
    /// When set, run entirely in userspace (gVisor netstack) and expose a SOCKS5
    /// proxy at this listen address (e.g. "0.0.0.0:1080" or "127.0.0.1:1080")
    /// instead of creating a kernel TUN device. No system interface, routes, DNS
    /// changes or root privileges are required. Only TCP CONNECT is supported.
    pub socks5_listen: Option<String>,
    /// Optional SOCKS5 username/password authentication (RFC 1929). When
    /// `socks5_username` is set and non-empty, clients must authenticate with
    /// these credentials; otherwise the proxy accepts connections without auth.
    pub socks5_username: Option<String>,
    pub socks5_password: Option<String>,
    /// Force the WireGuard transport protocol instead of using the server-advertised
    /// `protocol_mode`. Accepts "udp" or "tcp" (case-insensitive). Some `protocol_mode: 1`
    /// (TCP) gateways also accept WireGuard over UDP -- for those the server even ships a
    /// `protocol_detect_config` (udp<->tcp switch thresholds) in the `/api/vpn/list` entry.
    /// Since WireGuard-over-TCP can collapse to a few KB/s on a lossy uplink (TCP-over-TCP
    /// head-of-line blocking), forcing "udp" can be far faster there. Leave unset to keep the
    /// default (follow server `protocol_mode`: 1 => tcp, otherwise udp).
    pub force_protocol: Option<String>,
}

impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match serde_json::to_string_pretty(self) {
            Ok(s) => write!(f, "{}", s),
            Err(e) => write!(f, "<invalid config: {e}>"),
        }
    }
}

impl Config {
    pub fn effective_android_profile(&self) -> AndroidProfile {
        self.android_profile.clone().unwrap_or_default()
    }

    pub fn android_user_agent(&self) -> String {
        self.android_profile
            .as_ref()
            .map(AndroidProfile::user_agent)
            .unwrap_or_else(|| DEFAULT_ANDROID_USER_AGENT.to_string())
    }

    pub async fn from_file(file: &str) -> Result<Config> {
        let conf_str = fs::read_to_string(file)
            .await
            .with_context(|| format!("failed to read config file {file}"))?;

        let mut conf: Config = serde_json::from_str(&conf_str[..])
            .with_context(|| format!("failed to parse config file {file}"))?;

        conf.conf_file = Some(file.to_string());
        let mut update_conf = false;
        if conf.interface_name.is_none() {
            conf.interface_name = Some(DEFAULT_INTERFACE_NAME.to_string());
            update_conf = true;
        }
        if conf.device_name.is_none() {
            conf.device_name = Some(DEFAULT_DEVICE_NAME.to_string());
            update_conf = true;
        }
        if conf.device_id.is_none() {
            let device_name = conf
                .device_name
                .as_ref()
                .context("device name missing when generating device id")?;
            conf.device_id = Some(format!("{:x}", md5::compute(device_name)));
            update_conf = true;
        }
        match &conf.private_key {
            Some(private_key) => match conf.public_key {
                Some(_) => {
                    // both keys exist, do nothing
                }
                None => {
                    // only private key exists, generate public from private
                    let public_key = utils::gen_public_key_from_private(private_key)?;
                    conf.public_key = Some(public_key);
                    update_conf = true;
                }
            },
            None => {
                // no key exists, generate new
                let (public_key, private_key) = utils::gen_wg_keypair();
                (conf.public_key, conf.private_key) = (Some(public_key), Some(private_key));
                update_conf = true;
            }
        }
        if update_conf {
            conf.save().await?;
        }
        Ok(conf)
    }

    pub async fn save(&self) -> Result<()> {
        let file = self
            .conf_file
            .as_ref()
            .context("config file path missing")?;
        let data = format!("{}", &self);
        fs::write(file, data)
            .await
            .with_context(|| format!("failed to write config file {file}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn missing_android_profile_uses_current_official_identity() {
        let conf: Config = serde_json::from_value(json!({
            "company_name": "test",
            "username": "test"
        }))
        .unwrap();

        assert!(conf.android_profile.is_none());
        assert_eq!(
            conf.android_user_agent(),
            "CorpLink/3.3.16 (AndroidAndroid SDK built for arm64; Android 8.1.0; en)"
        );
        assert_eq!(conf.effective_android_profile(), AndroidProfile::default());
    }

    #[test]
    fn partial_android_profile_uses_defaults_for_unspecified_fields() {
        let conf: Config = serde_json::from_value(json!({
            "company_name": "test",
            "username": "test",
            "device_id": "stable-device-id",
            "android_profile": {
                "brand": "samsung",
                "model": "SM-S9210",
                "android_release": "14",
                "os_version": "34",
                "os_version_patch": "2025-04-01"
            }
        }))
        .unwrap();

        let profile = conf.effective_android_profile();
        assert_eq!(profile.app_version, "3.3.16");
        assert_eq!(profile.build_number, "2279");
        assert_eq!(profile.client_source, "FeiLian");
        assert_eq!(
            conf.android_user_agent(),
            "CorpLink/3.3.16 (samsungSM-S9210; Android 14; en)"
        );
        assert_eq!(conf.device_id.as_deref(), Some("stable-device-id"));
    }
}

#[derive(Serialize, Clone)]
pub struct WgConf {
    // standard wg conf
    pub address: String,
    pub address6: String,
    pub peer_address: String,
    pub mtu: u32,
    pub public_key: String,
    pub private_key: String,
    pub peer_key: String,
    pub allowed_ips: Vec<String>,
    pub routes: Vec<String>,

    // extra confs
    pub dns: String,

    // corplink confs
    /// `/vpn/conn` 分配的原始 IPv4 地址（不含 WireGuard CIDR 掩码）。
    /// `/vpn/report` 的 `ip` 字段要求使用此值，而不是 `address`。
    pub vpn_ip: String,
    pub protocol: i32,
}
