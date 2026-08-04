use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use std::{fs, io};

use anyhow::{anyhow, bail, Context, Result};
use chrono::Utc;
use cookie::Cookie as RawCookie;
use cookie_store::{Cookie, CookieStore};
use futures::stream::{FuturesUnordered, StreamExt};
use reqwest::cookie::CookieStore as ReqwestCookieStore;
use reqwest::header;
use reqwest::{ClientBuilder, Response, Url};
use reqwest_cookie_store::CookieStoreMutex;
use serde::de::DeserializeOwned;
use serde_json::{json, Map, Value};
use sha2::Digest;

use crate::api::{ApiName, ApiUrl, URL_GET_COMPANY};
use crate::config::{
    Config, WgConf, PLATFORM_CORPLINK, PLATFORM_CORPLINK_V1, PLATFORM_LARK, PLATFORM_LDAP,
    PLATFORM_OIDC, STRATEGY_DEFAULT, STRATEGY_LATENCY,
};
use crate::qrcode::TerminalQrCode;
use crate::resp::*;
use crate::sign;
use crate::state::State;
use crate::totp::{totp_offset, TIME_STEP};
use crate::utils;

const COOKIE_FILE_SUFFIX: &str = "cookies.json";
const SIGN_RETRY_CODES: [i32; 2] = [11020001, 11020002];
// Android 主进程在 VPN 已连接时约每两分钟刷新一次节点列表；响应会轮换
// vpn-token，VPN 进程再按一轮滞后的时序推进 jwt-token。四分钟会把旧 token
// 推到服务端容忍窗口边缘，轻微调度抖动就可能让 /vpn/report 返回 code 1000。
const VPN_TOKEN_REFRESH_INTERVAL: Duration = Duration::from_secs(120);
const VPN_REPORT_AUTH_REJECTED_CODE: i32 = 1000;

#[derive(Debug)]
struct VpnReportRejected {
    code: i32,
    message: String,
}

impl fmt::Display for VpnReportRejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "failed to report connection with error {}: {}",
            self.code, self.message
        )
    }
}

impl std::error::Error for VpnReportRejected {}

fn cookie_value<'a>(cookie_header: &'a str, expected_name: &str) -> Option<&'a str> {
    cookie_header
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(name, value)| (name == expected_name).then_some(value))
}

fn merge_additional_routes(
    mut routes: Vec<String>,
    additional_routes: &[String],
    has_ipv6_address: bool,
) -> Vec<String> {
    for route in additional_routes {
        if !crate::utils::is_valid_cidr(route) {
            log::warn!("ignoring invalid vpn_additional_routes CIDR: {:?}", route);
            continue;
        }
        if !has_ipv6_address && route.contains(':') {
            log::info!(
                "ignoring additional IPv6 route {:?} because the server did not assign an IPv6 address",
                route
            );
            continue;
        }
        if !routes.contains(route) {
            routes.push(route.clone());
        }
    }
    routes
}

async fn resolve_additional_domains(
    domains: &[String],
    has_ipv6_address: bool,
) -> Vec<String> {
    let mut routes = Vec::new();
    for configured_domain in domains {
        let domain = configured_domain.trim();
        if domain.is_empty() {
            log::warn!("ignoring empty vpn_additional_domains entry");
            continue;
        }

        match tokio::net::lookup_host((domain, 0)).await {
            Ok(addresses) => {
                let mut domain_routes = Vec::new();
                for address in addresses {
                    let ip = address.ip();
                    if ip.is_ipv6() && !has_ipv6_address {
                        continue;
                    }
                    let route = match ip {
                        std::net::IpAddr::V4(_) => format!("{ip}/32"),
                        std::net::IpAddr::V6(_) => format!("{ip}/128"),
                    };
                    if !domain_routes.contains(&route) {
                        domain_routes.push(route);
                    }
                }
                if domain_routes.is_empty() {
                    log::warn!(
                        "vpn_additional_domains entry {:?} returned no usable addresses",
                        domain
                    );
                } else {
                    log::info!(
                        "resolved additional VPN domain {:?} to {:?}",
                        domain,
                        domain_routes
                    );
                }
                for route in domain_routes {
                    if !routes.contains(&route) {
                        routes.push(route);
                    }
                }
            }
            Err(err) => {
                log::warn!(
                    "failed to resolve vpn_additional_domains entry {:?}: {}",
                    domain,
                    err
                );
            }
        }
    }
    routes
}

fn corplink_client_builder(user_agent: &str) -> ClientBuilder {
    ClientBuilder::new()
        // CorpLink deployments may use certificates signed by their own CA.
        .danger_accept_invalid_certs(true)
        // for debug
        // .proxy(reqwest::Proxy::all("socks5://192.168.111.233:8001").unwrap())
        .user_agent(user_agent)
        .timeout(Duration::from_millis(10000))
}

#[derive(Clone)]
pub struct Client {
    conf: Config,
    cookie: Arc<CookieStoreMutex>,
    c: reqwest::Client,
    probe_client: reqwest::Client,
    api_url: ApiUrl,
    date_offset_sec: i32,
    /// 数据面 `jwt-token` 请求头。官方客户端轮换 `vpn-token` Cookie 时，
    /// 当前 `/vpn/report` 仍使用旧 jwt-token；本次上报成功后，下一次才
    /// 将 jwt-token 推进到当前 Cookie 中的 token。
    vpn_jwt: Option<String>,
    vpn_token_refreshed_at: Option<Instant>,
}

struct VpnProbeResponse {
    latency_ms: i64,
    set_cookie_headers: Vec<header::HeaderValue>,
}

struct SelectedVpn {
    vpn: RespVpnInfo,
    set_cookie_headers: Vec<header::HeaderValue>,
}

unsafe impl Send for Client {}

unsafe impl Sync for Client {}

pub async fn get_company_url(code: &str) -> anyhow::Result<RespCompany> {
    let c = ClientBuilder::new()
        // allow invalid certs because this cert is signed by corplink
        .danger_accept_invalid_certs(true)
        .build()
        .context("build client")?;
    let mut m = Map::new();
    m.insert("code".to_string(), json!(code));
    let body = serde_json::to_string(&m).context("serialize company request body")?;

    let resp = c
        .post(URL_GET_COMPANY)
        .body(body)
        .send()
        .await
        .context("get company")?
        .json::<Resp<RespCompany>>()
        .await
        .context("parse company resp")?;
    match resp.code {
        0 => resp.data.context("company response missing data"),
        _ => Err(anyhow!(resp
            .message
            .unwrap_or_else(|| "failed to fetch company info".to_string()))),
    }
}

impl Client {
    pub fn new(conf: Config) -> Result<Client> {
        let f = conf.conf_file.clone().context("config file path missing")?;
        let interface_name = conf
            .interface_name
            .clone()
            .context("interface name missing in config")?;
        let dir = match path::Path::new(&f).parent() {
            Some(dir) => dir,
            None => path::Path::new("."),
        };
        let cookie_file = dir.join(format!("{}_{}", interface_name, COOKIE_FILE_SUFFIX));
        log::info!("cookie file is: {}", cookie_file.to_string_lossy());

        let mut cookie_store = {
            let file = fs::File::open(&cookie_file).map(io::BufReader::new);
            match file {
                Ok(file) => CookieStore::load_json_all(file).or_else(|e| {
                    bail!(
                        "failed to load cookie store from {}: {e}",
                        cookie_file.display()
                    )
                })?,
                Err(_) => CookieStore::default(),
            }
        };
        let has_expired = cookie_store.iter_any().any(|cookie| cookie.is_expired());
        if has_expired {
            log::info!("some cookies are expired");
        }

        if let Some(server) = conf.server.as_ref() {
            let server_url = Url::from_str(server.as_str())
                .with_context(|| format!("invalid server url: {server}"))?;

            if let Some(device_id) = conf.device_id.as_ref() {
                cookie_store
                    .insert_raw(&RawCookie::new("device_id", device_id), &server_url)
                    .context("failed to insert device_id cookie")?;
            }
            if let Some(device_name) = conf.device_name.as_ref() {
                cookie_store
                    .insert_raw(&RawCookie::new("device_name", device_name), &server_url)
                    .context("failed to insert device_name cookie")?;
            }
        }

        let cookie_store = Arc::new(CookieStoreMutex::new(cookie_store));
        let user_agent = conf.android_user_agent();

        // Keep probe responses out of the shared cookie store until an endpoint is selected.
        let probe_client = corplink_client_builder(&user_agent)
            .build()
            .context("build VPN probe HTTP client")?;
        let c = corplink_client_builder(&user_agent)
            .cookie_provider(Arc::clone(&cookie_store))
            .build()
            .context("build http client")?;
        let conf_bak = conf.clone();
        Ok(Client {
            conf,
            cookie: Arc::clone(&cookie_store),
            c,
            probe_client,
            api_url: ApiUrl::new(&conf_bak)?,
            date_offset_sec: 0,
            vpn_jwt: None,
            vpn_token_refreshed_at: None,
        })
    }

    async fn change_state(&mut self, state: State) -> Result<()> {
        self.conf.state = Some(state);
        self.conf.save().await?;
        Ok(())
    }

    fn save_cookie(&self) -> Result<()> {
        let interface_name = self
            .conf
            .interface_name
            .as_ref()
            .context("interface name missing in config")?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .append(false)
            .open(format!("{}_{}", interface_name, COOKIE_FILE_SUFFIX))
            .map(io::BufWriter::new)
            .with_context(|| "failed to open cookie file for writing")?;
        let c = self
            .cookie
            .lock()
            .map_err(|e| anyhow!("failed to lock cookie store: {e}"))?;
        c.save_json(&mut file)
            .or_else(|e| bail!("failed to persist cookies to disk: {e}"))?;
        Ok(())
    }

    async fn request<T: DeserializeOwned + fmt::Debug>(
        &mut self,
        api: ApiName,
        body: Option<Map<String, Value>>,
    ) -> Result<Resp<T>> {
        // body 不随重试变化：只序列化一次；body_bytes 借用 body_string，
        // 在整个函数生命周期内保持不变，循环内直接复用。
        let body_string: Option<String> = match &body {
            Some(b) => Some(
                serde_json::to_string(b)
                    .with_context(|| format!("failed to serialize request body for {api:?}"))?,
            ),
            None => None,
        };
        let body_bytes: &[u8] = body_string.as_deref().map(|s| s.as_bytes()).unwrap_or(b"");
        let method = if body_string.is_some() { "POST" } else { "GET" };

        for attempt in 0..2 {
            // 每轮重新构造 url，使重试自动用刷新后的 timestamp。
            let url_str = self.api_url.get_api_url(&api);
            let mut url = Url::from_str(&url_str)
                .with_context(|| format!("invalid api url {url_str} for {api:?}"))?;

            // timestamp（秒）加入 query：签名端点需要它进签名；数据面 /vpn/report（心跳/断连
            // 上报，不签名）也必须带 timestamp——服务端据此防重放，缺失会导致连续相同请求被判重放
            // 而返回 code 1000。真机客户端所有 /vpn/* 与 /api/* 请求均带 timestamp。
            let needs_timestamp =
                sign::sign_mask_by_path(url.path()).is_some() || url.path() == "/vpn/report";
            if needs_timestamp {
                let ts = self.current_timestamp().to_string();
                // 用 query_pairs_mut 追加，保持既有参数在前、timestamp 在后；
                // 之后签名与发送都用这个 url，保证逐字节一致。
                url.query_pairs_mut().append_pair("timestamp", &ts);
            }

            // 同一轮内冻结 Cookie/CSRF：签名值与实际请求头必须使用同一份 token。
            let cookie_str = self.cookie_header_for(&url)?;
            let csrf = cookie_value(&cookie_str, "csrf-token")
                .unwrap_or("")
                .to_owned();
            let cookie_jwt = cookie_value(&cookie_str, "vpn-token").map(str::to_owned);
            let is_data_plane = matches!(url.path(), "/vpn/conn" | "/vpn/report");
            let request_jwt = if is_data_plane {
                self.vpn_jwt.clone().or_else(|| cookie_jwt.clone())
            } else {
                cookie_jwt.clone()
            };
            let sign_header = self.build_sign_header_with_cookie(
                method,
                &url,
                body_bytes,
                &cookie_str,
                &csrf,
                request_jwt.as_deref().unwrap_or(""),
            )?;

            let mut rb = match &body_string {
                Some(b) => self
                    .c
                    .post(url.clone())
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(b.clone()),
                None => self.c.get(url.clone()),
            };

            if !csrf.is_empty() {
                rb = rb.header("csrf-token", &csrf);
            }
            if !cookie_str.is_empty() {
                rb = rb.header(header::COOKIE, &cookie_str);
            }
            // 数据面端点使用独立维护的 jwt-token；当 Cookie 中的 vpn-token
            // 轮换时，它会落后一轮，并在本次上报成功后推进。
            if let Some(jwt) = request_jwt.as_deref() {
                rb = rb.header("jwt-token", jwt);
            }
            if let Some((name, value)) = sign_header {
                log::debug!("signing {api:?} path={}", url.path());
                rb = rb.header(name, value);
            }

            let resp = rb
                .send()
                .await
                .with_context(|| format!("request {api:?} failed"))?;

            if !resp.status().is_success() {
                let msg = format!("logout because of bad resp code: {}", resp.status());
                self.handle_logout_err(msg).await?;
            }

            // 每轮 send 后刷新 offset，使下一轮重试用到最新时间偏移。
            self.parse_time_offset_from_date_header(&resp);

            for (name, _) in resp.headers() {
                if name.as_str().eq_ignore_ascii_case("set-cookie") {
                    log::info!("found set-cookie in header, saving cookie");
                    self.save_cookie()?;
                    break;
                }
            }
            let text = resp
                .text()
                .await
                .with_context(|| format!("failed to read response body for api {api:?}"))?;
            // 先解析通用 envelope，避免错误响应的 data 结构与 T 不一致时
            // 在调用方看到业务错误码之前就反序列化失败。
            let raw: Resp<Value> = serde_json::from_str(&text).with_context(|| {
                format!("failed to parse response envelope for api {api:?}: {text}")
            })?;

            // 真机时序：vpn-token Cookie 可能先轮换，但当前 /vpn/report 仍用
            // 旧 jwt-token；只有这次业务成功后，下一次上报才使用本次请求
            // Cookie 中的 token。不能直接使用响应后的 Cookie，否则会提前一轮。
            if raw.code == 0 && url.path() == "/vpn/report" {
                if let Some(cookie_jwt) = cookie_jwt {
                    self.vpn_jwt = Some(cookie_jwt);
                }
            }

            // 签名时间戳过期错误：刷新后重试一次
            if attempt == 0 && SIGN_RETRY_CODES.contains(&raw.code) {
                log::warn!("sign timestamp rejected (code {}), retrying once", raw.code);
                continue;
            }

            let data = match (raw.code, raw.data) {
                (0, Some(v)) => Some(
                    serde_json::from_value::<T>(v)
                        .with_context(|| format!("failed to parse response data for api {api:?}"))?,
                ),
                _ => None,
            };
            let resp = Resp::<T> {
                code: raw.code,
                message: raw.message,
                data,
                action: raw.action,
            };
            log::debug!("api {:#?} resp: {:#?}", api, resp);
            return Ok(resp);
        }

        bail!("request retry loop exhausted for {api:?}")
    }

    fn parse_time_offset_from_date_header(&mut self, resp: &Response) {
        if let Some(offset) = Self::time_offset_from_date_header(resp) {
            self.date_offset_sec = offset;
        }
    }

    fn time_offset_from_date_header(resp: &Response) -> Option<i32> {
        let headers = resp.headers();
        if let Some(date) = headers.get("date") {
            match date.to_str() {
                Ok(date) => match httpdate::parse_http_date(date) {
                    Ok(date) => {
                        let now = SystemTime::now();
                        let offset = if now < date {
                            let date_offset = date
                                .duration_since(now)
                                .unwrap_or_else(|_| Duration::from_secs(0));
                            date_offset.as_secs().try_into().unwrap_or_default()
                        } else {
                            let date_offset = now
                                .duration_since(date)
                                .unwrap_or_else(|_| Duration::from_secs(0));
                            let offset: i32 = date_offset.as_secs().try_into().unwrap_or_default();
                            -offset
                        };
                        return Some(offset);
                    }
                    Err(e) => {
                        log::warn!("failed to parse date in header, ignore it: {}", e);
                    }
                },
                Err(e) => log::warn!("failed to read date header: {}", e),
            }
        }
        None
    }

    pub fn need_login(&self) -> bool {
        matches!(self.conf.state.as_ref(), None | Some(State::Init))
    }

    async fn check_tps_token(&mut self, token: &String) -> Result<String> {
        // tps confirmed, try to login with token
        let mut m = Map::new();
        m.insert("token".to_string(), json!(token));

        let resp = self
            .request::<RespLogin>(ApiName::TpsTokenCheck, Some(m))
            .await?;
        match resp.code {
            0 => resp
                .data
                .context("tps token check missing redirect url")
                .map(|d| d.url),
            _ => {
                let msg = resp
                    .message
                    .unwrap_or_else(|| "tps token check failed".to_string());
                bail!(msg)
            }
        }
    }

    async fn get_otp_uri_from_tps(
        &mut self,
        method: &str,
        url: &String,
        token: &String,
    ) -> Result<String> {
        log::info!("old token is: {token}");
        log::info!("please scan the QR code or visit the following link to auth corplink:\n{url}");
        match TerminalQrCode::from_bytes(url.as_bytes()) {
            Ok(qr) => qr.print(),
            Err(e) => {log::warn!("failed to generate qr code: {e}");}
        }
        match method {
            PLATFORM_LARK | PLATFORM_OIDC => {
                log::info!("press enter if you finish auth");
                let stdin = io::stdin();
                stdin.lines().next();
                self.check_tps_token(token).await
            }
            _ => {
                // TODO: add all tps login support
                bail!("unsupported platform, please contact the developer");
            }
        }
    }

    async fn corplink_login(&mut self) -> Result<String> {
        let resp = self.get_corplink_login_method().await?;
        for method in resp.auth {
            match method.as_str() {
                "password" => {
                    if let Some(password) = &self.conf.password {
                        if !password.is_empty() {
                            log::info!("try to login with password");
                            return self.login_with_password(PLATFORM_CORPLINK).await;
                        }
                    }
                    log::info!("no password provided, trying other methods");
                    continue;
                }
                "email" => {
                    log::info!("try to login with code from email");
                    return self.login_with_email().await;
                }
                _ => {
                    log::info!("unsupported method {method}, trying other methods");
                }
            }
        }
        bail!("failed to login with corplink")
    }

    async fn ldap_login(&mut self) -> Result<String> {
        // I don't know why but we must get login method before login
        let resp = self.get_corplink_login_method().await?;
        for method in resp.auth {
            if method != "password" {
                continue;
            }
            if let Some(password) = &self.conf.password {
                return if !password.is_empty() {
                    self.login_with_password(PLATFORM_LDAP).await
                } else {
                    bail!("no password provided")
                };
            }
        }
        bail!("failed to login with ldap")
    }

    fn is_platform_or_default(&self, platform: &str) -> bool {
        if let Some(p) = &self.conf.platform {
            return p.is_empty() || platform == p;
        }
        true
    }

    async fn request_otp_code(&mut self) -> Result<String> {
        let m = Map::new();
        let resp = self.request::<RespOtp>(ApiName::Otp, Some(m)).await?;
        match resp.code {
            0 => Ok(resp.data.context("otp response missing data")?.url),
            _ => {
                let msg = resp
                    .message
                    .unwrap_or_else(|| "request otp code failed".to_string());
                bail!(msg)
            }
        }
    }

    async fn get_otp_uri_by_otp(
        &mut self,
        tps_login: &HashMap<String, RespTpsLoginMethod>,
        method: &String,
    ) -> Result<String> {
        let url = self.get_otp_uri(tps_login, method).await?;
        if url.is_empty() {
            self.request_otp_code().await
        } else {
            Ok(url)
        }
    }
    async fn get_otp_uri(
        &mut self,
        tps_login: &HashMap<String, RespTpsLoginMethod>,
        method: &String,
    ) -> Result<String> {
        if let Some(resp) = tps_login
            .get(method)
            .filter(|_| self.is_platform_or_default(method))
        {
            log::info!("try to login with third party platform {method}");
            return self
                .get_otp_uri_from_tps(method, &resp.login_url, &resp.token)
                .await;
        }
        match method.as_str() {
            PLATFORM_CORPLINK => {
                if self.is_platform_or_default(PLATFORM_CORPLINK) {
                    log::info!("try to login with platform {PLATFORM_CORPLINK}");
                    return self.corplink_login().await;
                }
            }
            PLATFORM_LDAP => {
                if self.is_platform_or_default(PLATFORM_LDAP) {
                    log::info!("try to login with platform {PLATFORM_LDAP}");
                    return self.ldap_login().await;
                }
            }
            _ => {}
        }
        Ok(String::new())
    }

    // new feilian v1 login (/api/v1/login with AES-encrypted password).
    // opt-in via `"platform": "feilian_v1"`; the old login paths are untouched.
    async fn login_v1(&mut self) -> Result<()> {
        let password = self
            .conf
            .password
            .as_ref()
            .filter(|p| !p.is_empty())
            .context("platform feilian_v1 requires a password")?
            .clone();
        log::info!("try to login with platform feilian_v1");
        let enc = utils::feilian_v1_encrypt_password(&password);
        let mut m = Map::new();
        m.insert("login_scene".to_string(), json!(PLATFORM_CORPLINK));
        m.insert("account_type".to_string(), json!("userid"));
        m.insert("account".to_string(), json!(&self.conf.username));
        m.insert("password".to_string(), json!(enc));

        let resp = self
            .request::<RespLoginV1>(ApiName::LoginPasswordV1, Some(m))
            .await?;
        match resp.code {
            0 => {
                let data = resp.data.context("v1 login response missing data")?;
                if data.result != "success" {
                    bail!("v1 login returned unexpected result: {}", data.result);
                }
                log::info!("login success");
                self.change_state(State::Login).await?;

                // fetch the TOTP secret so 2fa codes can be generated locally,
                // mirroring the legacy login() flow. the v1 backend serves the
                // same /api/v2/p/otp endpoint and otpauth uri format.
                match self.request_otp_code().await {
                    Ok(otp_uri) if !otp_uri.is_empty() => {
                        let url = Url::parse(&otp_uri).context("failed to parse otp uri")?;
                        for (k, v) in url.query_pairs() {
                            if k == "secret" {
                                log::info!("got 2fa token: {}", &v);
                                self.conf.code = Some(v.to_string());
                                self.conf.save().await?;
                                break;
                            }
                        }
                    }
                    Ok(_) => {
                        log::info!(
                            "no otp code from server, will ask for 2fa code when connecting"
                        );
                    }
                    Err(e) => log::warn!("failed to get otp code: {e}"),
                }
                Ok(())
            }
            _ => {
                let msg = resp
                    .message
                    .unwrap_or_else(|| "v1 login failed".to_string());
                bail!(msg)
            }
        }
    }

    // choose right login method and login
    pub async fn login(&mut self) -> Result<()> {
        if self.conf.platform.as_deref() == Some(PLATFORM_CORPLINK_V1) {
            return self.login_v1().await;
        }
        let resp = self.get_login_method().await?;
        let tps_login_resp = self.get_tps_login_method().await?;
        let mut tps_login = HashMap::new();
        for resp in tps_login_resp {
            tps_login.insert(resp.alias.clone(), resp);
        }
        for method in resp.login_orders {
            let otp_uri = self.get_otp_uri_by_otp(&tps_login, &method).await;
            if let Err(e) = otp_uri {
                log::warn!("failed to login with method {method}: {e}");
                continue;
            }
            let otp_uri = otp_uri?;
            if otp_uri.is_empty() {
                log::info!("no otp code from server, will ask for 2fa code when connecting");
                self.change_state(State::Login).await?;
                return Ok(());
            }
            self.change_state(State::Login).await?;

            let url = Url::parse(&otp_uri).context("failed to parse otp uri")?;
            for (k, v) in url.query_pairs() {
                if k == "secret" {
                    log::info!("got 2fa token: {}", &v);
                    self.conf.code = Some(v.to_string());
                    self.conf.save().await?;
                    break;
                }
            }

            if let Some(code) = &self.conf.code {
                if !code.is_empty() {
                    return Ok(());
                }
            }
            log::warn!("failed to get otp code");
            return Ok(());
        }
        bail!("no available login method, please provide a valid platform")
    }

    async fn get_login_method(&mut self) -> Result<RespLoginMethod> {
        let resp = self
            .request::<RespLoginMethod>(ApiName::LoginMethod, None)
            .await?;
        resp.data.context("login method response missing data")
    }

    // get 3rd party login methods and links, only lark(feishu) is tested
    async fn get_tps_login_method(&mut self) -> Result<Vec<RespTpsLoginMethod>> {
        let resp = self
            .request::<Vec<RespTpsLoginMethod>>(ApiName::TpsLoginMethod, None)
            .await?;
        Ok(resp.data.unwrap_or_default())
    }

    // get corplink login method, knowing result can be password or email
    async fn get_corplink_login_method(&mut self) -> Result<RespCorplinkLoginMethod> {
        let mut m = Map::new();
        m.insert("forget_password".to_string(), json!(false));
        m.insert("user_name".to_string(), json!(&self.conf.username));

        let resp = self
            .request::<RespCorplinkLoginMethod>(ApiName::CorplinkLoginMethod, Some(m))
            .await?;
        resp.data
            .context("corplink login method response missing data")
    }

    async fn login_with_password(&mut self, platform: &str) -> Result<String> {
        let mut password = self
            .conf
            .password
            .as_ref()
            .context("password is required for password login")?
            .clone();
        let mut m = Map::new();
        match platform {
            PLATFORM_LDAP => {
                m.insert("platform".to_string(), json!(PLATFORM_LDAP));
            }
            PLATFORM_CORPLINK => {
                if password.len() != 64 {
                    let mut sha = sha2::Sha256::new();
                    sha.update(password.as_bytes());
                    password = format!("{:x}", sha.finalize());
                } // else: password already convert to sha256sum
            }
            _ => {
                bail!("invalid platform {platform}")
            }
        }
        m.insert("password".to_string(), json!(password));
        m.insert("user_name".to_string(), json!(&self.conf.username));

        let resp = self
            .request::<RespLogin>(ApiName::LoginPassword, Some(m))
            .await?;
        match resp.code {
            0 => Ok(resp
                .data
                .context("password login response missing data")?
                .url),
            _ => {
                let msg = resp
                    .message
                    .unwrap_or_else(|| "login with password failed".to_string());
                bail!(msg)
            }
        }
    }

    async fn request_email_code(&mut self) -> Result<()> {
        let mut m = Map::new();
        m.insert("forget_password".to_string(), json!(false));
        m.insert("code_type".to_string(), json!("email"));
        m.insert("user_name".to_string(), json!(&self.conf.username));

        self.request::<Map<String, Value>>(ApiName::RequestEmailCode, Some(m))
            .await?;
        Ok(())
    }

    async fn login_with_email(&mut self) -> Result<String> {
        // tell server to send code to email
        log::info!("try to request code for email");
        self.request_email_code().await?;

        log::info!("input your code from email:");
        let input = utils::read_line().await?;
        let code = input.trim();
        let mut m = Map::new();
        m.insert("forget_password".to_string(), json!(false));
        m.insert("code_type".to_string(), json!("email"));
        m.insert("code".to_string(), json!(code));

        let resp = self
            .request::<RespLogin>(ApiName::LoginEmail, Some(m))
            .await?;
        match resp.code {
            0 => Ok(resp.data.context("email login response missing data")?.url),
            _ => bail!(format!(
                "failed to login with email code {}: {}",
                code,
                resp.message.unwrap_or_else(|| "unknown error".to_string())
            )),
        }
    }

    async fn handle_logout_err(&mut self, msg: String) -> Result<()> {
        self.change_state(State::Init)
            .await
            .context("failed to reset state after logout")?;
        bail!("operation failed because of logout: {msg}")
    }

    async fn list_vpn(&mut self) -> Result<Vec<RespVpnInfo>> {
        let resp = self
            .request::<Vec<RespVpnInfo>>(ApiName::ListVPN, None)
            .await?;
        match resp.code {
            0 => resp.data.context("list vpn response missing data"),
            101 => {
                let msg = resp
                    .message
                    .unwrap_or_else(|| "logout required".to_string());
                self.handle_logout_err(msg).await?;
                unreachable!()
            }
            _ => bail!(format!(
                "failed to list vpn with error {}: {}",
                resp.code,
                resp.message.unwrap_or_default()
            )),
        }
    }

    async fn get_first_vpn_by_latency(&self, vpn_info: Vec<RespVpnInfo>) -> Option<SelectedVpn> {
        let mut fastest: Option<(i64, usize, SelectedVpn)> = None;

        let mut probes = vpn_info
            .into_iter()
            .enumerate()
            .map(|(index, vpn)| async move {
                let result = self.ping_vpn(&vpn.ip, vpn.api_port).await;
                (index, vpn, result)
            })
            .collect::<FuturesUnordered<_>>();

        while let Some((index, vpn, result)) = probes.next().await {
            match result {
                Ok(response) => {
                    log::info!(
                        "server name {}, latency {}ms",
                        vpn.display_name(),
                        response.latency_ms
                    );
                    let should_replace = match &fastest {
                        Some((latency, best_index, _)) => {
                            (response.latency_ms, index) < (*latency, *best_index)
                        }
                        None => true,
                    };
                    if should_replace {
                        fastest = Some((
                            response.latency_ms,
                            index,
                            SelectedVpn {
                                vpn,
                                set_cookie_headers: response.set_cookie_headers,
                            },
                        ));
                    }
                }
                Err(err) => {
                    log::warn!("failed to ping {}:{}: {}", vpn.ip, vpn.api_port, err);
                }
            }
        }
        fastest.map(|(_, _, vpn)| vpn)
    }

    async fn get_first_available_vpn(&self, vpn_info: Vec<RespVpnInfo>) -> Option<SelectedVpn> {
        // Probes finish out of order, but the default strategy follows server-list priority.
        let mut results = std::iter::repeat_with(|| None)
            .take(vpn_info.len())
            .collect::<Vec<_>>();
        let mut next_index = 0;
        let mut probes = vpn_info
            .into_iter()
            .enumerate()
            .map(|(index, vpn)| async move {
                let result = self.ping_vpn(&vpn.ip, vpn.api_port).await;
                (index, vpn, result)
            })
            .collect::<FuturesUnordered<_>>();

        while let Some((index, vpn, result)) = probes.next().await {
            results[index] = Some((vpn, result));

            while next_index < results.len() {
                let Some((vpn, result)) = results[next_index].take() else {
                    break;
                };
                next_index += 1;

                match result {
                    Ok(response) => {
                        log::info!(
                            "server name {}, latency {}ms",
                            vpn.display_name(),
                            response.latency_ms
                        );
                        return Some(SelectedVpn {
                            vpn,
                            set_cookie_headers: response.set_cookie_headers,
                        });
                    }
                    Err(err) => {
                        log::warn!("failed to ping {}:{}: {}", vpn.ip, vpn.api_port, err);
                    }
                }
            }
        }
        None
    }

    /// 当前时间戳（秒），已按服务器 Date 头校正。
    fn current_timestamp(&self) -> i64 {
        Utc::now().timestamp() + self.date_offset_sec as i64
    }

    /// 按 cookie jar 顺序拼 "name=value"，用 "; " 连接（供签名的 cookieStr 用）。
    /// 顺序须与 reqwest 实际发送的 Cookie 头一致——两者都源自同一 jar。
    fn cookie_header_for(&self, url: &Url) -> Result<String> {
        let store = self
            .cookie
            .lock()
            .map_err(|e| anyhow!("failed to lock cookie store: {e}"))?;
        let pairs: Vec<String> = store
            .get_request_values(url)
            .map(|(name, value)| format!("{name}={value}"))
            .collect();
        Ok(pairs.join("; "))
    }

    /// 若该 path 需要签名，返回 (header_name, header_value)。
    #[cfg(test)]
    fn build_sign_header(
        &self,
        method: &str,
        url: &Url,
        body: &[u8],
    ) -> Result<Option<(String, String)>> {
        let cookie_str = self.cookie_header_for(url)?;
        let csrf = cookie_value(&cookie_str, "csrf-token").unwrap_or("");
        let jwt = cookie_value(&cookie_str, "vpn-token").unwrap_or("");

        self.build_sign_header_with_cookie(method, url, body, &cookie_str, csrf, jwt)
    }

    fn build_sign_header_with_cookie(
        &self,
        method: &str,
        url: &Url,
        body: &[u8],
        cookie_str: &str,
        csrf: &str,
        jwt: &str,
    ) -> Result<Option<(String, String)>> {
        let path = url.path();
        let mask = match sign::sign_mask_by_path(path) {
            Some(m) => m,
            None => return Ok(None),
        };
        let company = &self.conf.company_name;
        let device_id = self
            .conf
            .device_id
            .as_deref()
            .context("device_id required for request signing")?;
        if csrf.is_empty() && (mask >> 7) & 1 == 1 {
            log::warn!(
                "no csrf-token cookie for signed endpoint {} (mask {:#x}); signing with empty csrf, signature may be rejected",
                url.path(),
                mask
            );
        }
        if jwt.is_empty() && (mask >> 9) & 1 == 1 {
            log::warn!(
                "no vpn-token cookie for signed endpoint {} (mask {:#x}); signing with empty jwt, signature may be rejected",
                url.path(),
                mask
            );
        }
        let query = url.query().unwrap_or("");
        let value = sign::compute_sign(
            company, device_id, method, path, query, body, cookie_str, csrf, jwt, mask,
        );
        Ok(Some((sign::SIGN_HEADER.to_string(), value)))
    }

    fn vpn_endpoint_url(&self, host: &str, api_port: u16) -> Result<Url> {
        let server_url = self
            .conf
            .server
            .as_ref()
            .context("server url is required to configure vpn endpoint")?;
        let server_url = Url::from_str(server_url)
            .with_context(|| format!("invalid server url: {server_url}"))?;
        let mut endpoint_url = Url::parse(&format!("{}://localhost", server_url.scheme()))
            .context("failed to construct vpn endpoint URL")?;
        match host.parse::<IpAddr>() {
            Ok(ip) => endpoint_url
                .set_ip_host(ip)
                .map_err(|_| anyhow!("failed to set vpn endpoint IP"))?,
            Err(_) => endpoint_url
                .set_host(Some(host))
                .context("failed to set vpn endpoint host")?,
        }
        endpoint_url
            .set_port(Some(api_port))
            .map_err(|_| anyhow!("failed to set vpn endpoint port"))?;
        Ok(endpoint_url)
    }

    fn probe_cookie_header(&self) -> Result<Option<header::HeaderValue>> {
        let server_url = self
            .conf
            .server
            .as_ref()
            .context("server url is required to prepare VPN probe cookies")?;
        let server_url = Url::from_str(server_url)
            .with_context(|| format!("invalid server url: {server_url}"))?;
        Ok(ReqwestCookieStore::cookies(
            self.cookie.as_ref(),
            &server_url,
        ))
    }

    fn sync_gateway_cookies_to_endpoint(&self, url: &Url) -> Result<()> {
        // 把网关域(server)的会话 cookie 复制到数据面 IP host，使随后 /vpn/conn、/vpn/report
        // 请求在该 host 上带上 session/csrf/vpn-token（这些是网关域 HostOnly cookie，不会自动
        // 匹配数据面 IP host）。
        {
            let mut cookie_store = self
                .cookie
                .lock()
                .map_err(|e| anyhow!("failed to lock cookie store: {e}"))?;
            let server_url = self
                .conf
                .server
                .as_ref()
                .context("server url is required to configure vpn endpoint")?;
            let server_url = Url::from_str(server_url)
                .with_context(|| format!("invalid server url: {server_url}"))?;
            let cookies: Vec<Cookie> = cookie_store
                .iter_any()
                .filter(|cookie| !cookie.is_expired() && cookie.domain.matches(&server_url))
                .cloned()
                .collect();
            for cookie in cookies {
                let raw_cookie =
                    cookie::Cookie::new(cookie.name().to_string(), cookie.value().to_string());
                let endpoint_cookie = Cookie::try_from_raw_cookie(&raw_cookie, url)
                    .context("failed to convert raw cookie")?;
                cookie_store
                    .insert(endpoint_cookie, url)
                    .context("failed to insert vpn endpoint cookie")?;
            }
        }
        Ok(())
    }

    fn sync_gateway_vpn_token_to_endpoint(&self, url: &Url) -> Result<()> {
        let server_url = self
            .conf
            .server
            .as_ref()
            .context("server url is required to refresh VPN token")?;
        let server_url = Url::from_str(server_url)
            .with_context(|| format!("invalid server url: {server_url}"))?;
        let gateway_cookie = self.cookie_header_for(&server_url)?;
        let vpn_token = cookie_value(&gateway_cookie, "vpn-token")
            .context("gateway vpn-token missing after refresh")?;

        // 只把轮换后的 vpn-token 送进数据面 Cookie。数据面的 session/csrf-token
        // 属于建连身份，覆盖成控制面刚刷新的值会让网关立即返回 code 1000。
        let raw_cookie = RawCookie::new("vpn-token", vpn_token.to_string());
        let endpoint_cookie = Cookie::try_from_raw_cookie(&raw_cookie, url)
            .context("failed to convert refreshed vpn-token")?;
        self.cookie
            .lock()
            .map_err(|e| anyhow!("failed to lock cookie store: {e}"))?
            .insert(endpoint_cookie, url)
            .context("failed to install refreshed vpn-token")?;
        Ok(())
    }

    fn prepare_vpn_endpoint(&mut self, ip: &str, api_port: u16) -> Result<Url> {
        let url = self.vpn_endpoint_url(ip, api_port)?;
        self.sync_gateway_cookies_to_endpoint(&url)?;
        self.api_url.vpn_param.url = url.to_string().trim_end_matches('/').to_string();
        Ok(url)
    }

    async fn refresh_vpn_token(&mut self) -> Result<()> {
        let endpoint_url = Url::from_str(&self.api_url.vpn_param.url)
            .context("invalid active VPN endpoint URL")?;

        // Android 会通过控制面请求轮换 vpn-token，但 VPN 进程仍保留原来的
        // session/csrf-token。复用列表接口触发续期后，只同步 vpn-token。
        self.list_vpn().await?;
        self.sync_gateway_vpn_token_to_endpoint(&endpoint_url)?;
        self.vpn_token_refreshed_at = Some(Instant::now());
        Ok(())
    }

    fn align_vpn_jwt_to_endpoint_cookie(&mut self) -> Result<()> {
        let endpoint_url = Url::from_str(&self.api_url.vpn_param.url)
            .context("invalid active VPN endpoint URL")?;
        let endpoint_cookie = self.cookie_header_for(&endpoint_url)?;
        let vpn_token = cookie_value(&endpoint_cookie, "vpn-token")
            .context("VPN endpoint vpn-token missing while recovering report authentication")?;
        self.vpn_jwt = Some(vpn_token.to_owned());
        Ok(())
    }

    async fn recover_vpn_report_auth(&mut self, conf: &WgConf) -> Result<()> {
        // code 1000 可能是刷新间隔边缘上的 Cookie/jwt-token 不同步。先从
        // 控制面重新取得 token，再让数据面的两个 token 对齐。正常路径仍保留
        // 官方客户端的一轮滞后；这里只处理已经被服务端拒绝后的单次恢复。
        self.refresh_vpn_token()
            .await
            .context("failed to refresh VPN token during report recovery")?;
        self.align_vpn_jwt_to_endpoint_cookie()?;

        // /vpn/report 使用秒级 timestamp。避免恢复请求和刚失败的请求落在同一秒，
        // 被服务端继续当成重放。
        tokio::time::sleep(Duration::from_secs(1)).await;
        self.report_vpn_status(conf)
            .await
            .context("VPN report retry after token resync failed")
    }

    // ping vpn and return latency in ms. Will return Err on error
    async fn ping_vpn(&self, ip: &str, api_port: u16) -> Result<VpnProbeResponse> {
        let endpoint_url = self.vpn_endpoint_url(ip, api_port)?;
        let mut api_url = self.api_url.clone();
        api_url.vpn_param.url = endpoint_url.to_string().trim_end_matches('/').to_string();

        let cookie_header = self.probe_cookie_header()?;
        let cookie_str = match cookie_header.as_ref() {
            Some(value) => value
                .to_str()
                .context("VPN probe Cookie header is not valid text")?
                .to_owned(),
            None => String::new(),
        };
        let csrf = cookie_value(&cookie_str, "csrf-token")
            .unwrap_or("")
            .to_owned();
        let started = Instant::now();
        let mut date_offset_sec = self.date_offset_sec;

        for attempt in 0..2 {
            let url_str = api_url.get_api_url(&ApiName::PingVPN);
            let mut url = Url::from_str(&url_str)
                .with_context(|| format!("invalid VPN probe url {url_str}"))?;
            let timestamp = Utc::now().timestamp() + date_offset_sec as i64;
            url.query_pairs_mut()
                .append_pair("timestamp", &timestamp.to_string());
            let sign_header =
                self.build_sign_header_with_cookie(
                    "GET",
                    &url,
                    b"",
                    &cookie_str,
                    &csrf,
                    cookie_value(&cookie_str, "vpn-token").unwrap_or(""),
                )?;

            let mut request = self.probe_client.get(url);
            if let Some(cookies) = cookie_header.as_ref() {
                request = request.header(header::COOKIE, cookies);
            }
            if !csrf.is_empty() {
                request = request.header("csrf-token", &csrf);
            }
            if let Some(jwt) = cookie_value(&cookie_str, "vpn-token") {
                request = request.header("jwt-token", jwt);
            }
            if let Some((name, value)) = sign_header {
                request = request.header(name, value);
            }

            let response = request.send().await.context("VPN probe request failed")?;
            if let Some(offset) = Self::time_offset_from_date_header(&response) {
                date_offset_sec = offset;
            }
            let status = response.status();
            let set_cookie_headers = response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .cloned()
                .collect();
            let body = response
                .text()
                .await
                .context("failed to read VPN probe response body")?;

            if !status.is_success() {
                bail!("VPN probe returned HTTP status {status}");
            }
            let resp: Resp<Value> = serde_json::from_str(&body)
                .with_context(|| format!("failed to parse VPN probe response: {body}"))?;
            if attempt == 0 && SIGN_RETRY_CODES.contains(&resp.code) {
                log::warn!(
                    "VPN probe sign timestamp rejected (code {}), retrying once",
                    resp.code
                );
                continue;
            }
            return match resp.code {
                0 => Ok(VpnProbeResponse {
                    latency_ms: started.elapsed().as_millis().min(i64::MAX as u128) as i64,
                    set_cookie_headers,
                }),
                _ => bail!(format!(
                    "failed to ping vpn with error {}: {}",
                    resp.code,
                    resp.message.unwrap_or_default()
                )),
            };
        }

        bail!("VPN probe retry loop exhausted")
    }

    async fn fetch_peer_info(&mut self, public_key: &String) -> Result<RespWgInfo> {
        let mut otp = String::new();
        if let Some(code) = &self.conf.code {
            if !code.is_empty() {
                let code = utils::b32_decode(code)?;
                let offset = self.date_offset_sec / TIME_STEP as i32;
                let raw_otp = totp_offset(code.as_slice(), offset);
                otp = format!("{:06}", raw_otp.code);
                log::info!(
                    "2fa code generated: {}, {} seconds left",
                    &otp,
                    raw_otp.secs_left
                );
            }
        }
        if otp.is_empty() {
            let is_tps_login = matches!(
                self.conf.platform.as_deref(),
                Some(PLATFORM_LARK | PLATFORM_OIDC)
            );
            if is_tps_login {
                log::info!("use empty 2fa code (tps login already verified)");
            } else {
                log::info!("input your 2fa code:");
                otp = utils::read_line().await?;
            }
        }
        let mut m = Map::new();
        m.insert("public_key".to_string(), json!(public_key));
        m.insert("otp".to_string(), json!(otp));
        // 与真机客户端一致：/vpn/conn body 还需 mode/export_id/not_auto。
        m.insert(
            "mode".to_string(),
            json!(match self.conf.route_mode.clone().unwrap_or_default() {
                crate::config::RouteMode::Split => "Split",
                crate::config::RouteMode::Full => "Full",
            }),
        );
        m.insert("export_id".to_string(), json!(0));
        m.insert("not_auto".to_string(), json!(false));
        let resp = self
            .request::<RespWgInfo>(ApiName::ConnectVPN, Some(m))
            .await?;
        match resp.code {
            0 => resp.data.context("connect vpn response missing data"),
            101 => {
                let msg = resp
                    .message
                    .unwrap_or_else(|| "logout required".to_string());
                self.handle_logout_err(msg).await?;
                unreachable!()
            }
            _ => bail!(format!(
                "failed to fetch peer info with error {}: {}",
                resp.code,
                resp.message.unwrap_or_default()
            )),
        }
    }

    pub async fn connect_vpn(&mut self) -> Result<WgConf> {
        let vpn_info = self.list_vpn().await?;

        log::info!(
            "found {} vpn(s), details: {:?}",
            vpn_info.len(),
            vpn_info
                .iter()
                .map(|i| i.display_name().to_string())
                .collect::<Vec<String>>()
        );
        let filtered_vpn = vpn_info
            .into_iter()
            .filter(|vpn| {
                if let Some(server_name) = self.conf.vpn_server_name.clone() {
                    if vpn.display_name() != server_name {
                        log::info!("skip {}, expect {}", vpn.display_name(), server_name);
                        return false;
                    }
                }
                true
            })
            .filter(|vpn| {
                let mode = match vpn.protocol_mode {
                    1 => "tcp",
                    2 => "udp",
                    _ => "unknown protocol",
                };
                match mode {
                    "udp" => true,
                    "tcp" => true,
                    _ => {
                        log::info!(
                            "server name {} is not support {} wg for now",
                            vpn.display_name(),
                            mode
                        );
                        false
                    }
                }
            })
            .collect();

        let vpn = match self.conf.vpn_select_strategy.clone() {
            Some(strategy) => match strategy.as_str() {
                STRATEGY_LATENCY => self.get_first_vpn_by_latency(filtered_vpn).await,
                STRATEGY_DEFAULT => self.get_first_available_vpn(filtered_vpn).await,
                _ => bail!("unsupported strategy"),
            },
            None => self.get_first_available_vpn(filtered_vpn).await,
        };

        let selected_vpn = vpn.context("no vpn available")?;
        let vpn = &selected_vpn.vpn;
        let endpoint_url = self.prepare_vpn_endpoint(&vpn.ip, vpn.api_port)?;
        // Persist only cookies returned by the selected endpoint probe.
        ReqwestCookieStore::set_cookies(
            self.cookie.as_ref(),
            &mut selected_vpn.set_cookie_headers.iter(),
            &endpoint_url,
        );
        // `/vpn/conn` 的签名和 jwt-token 请求头从选中节点探测后得到的
        // vpn-token 起步；后续 `/vpn/report` 按官方客户端的一轮滞后时序推进。
        let endpoint_cookie = self.cookie_header_for(&endpoint_url)?;
        self.vpn_jwt = cookie_value(&endpoint_cookie, "vpn-token").map(str::to_owned);
        self.save_cookie()?;
        let vpn_addr = match vpn.ip.parse::<IpAddr>() {
            Ok(ip) => SocketAddr::new(ip, vpn.vpn_port).to_string(),
            Err(_) => format!("{}:{}", vpn.ip, vpn.vpn_port),
        };
        log::info!(
            "try connect to {}, address {}",
            vpn.display_name(),
            vpn_addr
        );

        let key = self
            .conf
            .public_key
            .as_ref()
            .context("public key missing in config")?
            .clone();
        log::info!("try to get wg conf from remote");
        let wg_info = self.fetch_peer_info(&key).await?;
        let mtu = wg_info.setting.vpn_mtu;
        let dns = wg_info.setting.vpn_dns;
        let peer_key = wg_info.public_key;
        let public_key = self
            .conf
            .public_key
            .as_ref()
            .context("public key missing in config")?
            .clone();
        let private_key = self
            .conf
            .private_key
            .as_ref()
            .context("private key missing in config")?
            .clone();
        let ip_mask = wg_info.ip_mask.parse::<u32>().context("invalid ip mask")?;
        let vpn_ip = wg_info.ip;
        let address = format!("{vpn_ip}/{ip_mask}");
        let has_ipv6_address = !wg_info.ipv6.is_empty();
        let address6 = has_ipv6_address
            .then_some(format!("{}/128", wg_info.ipv6))
            .unwrap_or_default();
        let mut allowed_ips = match self.conf.route_mode.clone().unwrap_or_default() {
            crate::config::RouteMode::Split => {
                log::info!("route_mode = split");
                let mut routes = wg_info.setting.vpn_route_split;
                let v6 = wg_info.setting.v6_route_split.unwrap_or_default();
                if has_ipv6_address {
                    routes.extend(v6);
                } else if !v6.is_empty() {
                    log::info!(
                        "ignoring {} IPv6 split routes because the server did not assign an IPv6 address",
                        v6.len()
                    );
                }
                routes
            }
            crate::config::RouteMode::Full => {
                log::info!("route_mode = full");
                let v4 = wg_info.setting.vpn_route_full;
                let v6 = wg_info.setting.v6_route_full.unwrap_or_default();
                log::info!(
                    "route_mode=full, server returned vpn_route_full ({} entries): {:?}",
                    v4.len(),
                    v4
                );
                log::info!(
                    "route_mode=full, server returned v6_route_full ({} entries): {:?}",
                    v6.len(),
                    v6
                );
                let mut routes = v4;
                if has_ipv6_address {
                    routes.extend(v6);
                } else if !v6.is_empty() {
                    log::info!(
                        "ignoring {} IPv6 full-tunnel routes because the server did not assign an IPv6 address",
                        v6.len()
                    );
                }
                if routes.is_empty() {
                    bail!(
                        "route_mode=full but server returned no usable routes; \
                         refuse to fall back to 0.0.0.0/0 to avoid peer-IP routing loop that blocks all traffic"
                    );
                }
                routes
            }
        };

        let mut additional_routes = self
            .conf
            .vpn_additional_routes
            .clone()
            .unwrap_or_default();
        if let Some(domains) = self.conf.vpn_additional_domains.as_deref() {
            additional_routes
                .extend(resolve_additional_domains(domains, has_ipv6_address).await);
        }
        if !additional_routes.is_empty() {
            let before = allowed_ips.len();
            allowed_ips = merge_additional_routes(
                allowed_ips,
                &additional_routes,
                has_ipv6_address,
            );
            log::info!(
                "additional VPN routes merged: {} -> {} entries",
                before,
                allowed_ips.len()
            );
        }

        // Restrict server and user-added routes to the optional whitelist, then
        // carve out the optional denylist. A configured empty whitelist
        // intentionally yields no AllowedIPs/routes; invalid entries fail closed.
        if let Some(allowed) = self.conf.vpn_allowed_routes.as_deref() {
            for route in allowed {
                if !crate::utils::is_valid_cidr(route) {
                    log::warn!("ignoring invalid vpn_allowed_routes CIDR: {:?}", route);
                }
            }
        }
        let before = allowed_ips.len();
        allowed_ips = crate::utils::apply_route_filters(
            &allowed_ips,
            self.conf.vpn_allowed_routes.as_deref(),
            self.conf.vpn_disallowed_routes.as_deref(),
        );
        if self.conf.vpn_allowed_routes.is_some() || self.conf.vpn_disallowed_routes.is_some() {
            log::info!(
                "VPN route filters applied: {} -> {} entries",
                before,
                allowed_ips.len()
            );
        }

        // Auto-carve the VPN peer endpoint IP out of allowed_ips. In full-tunnel mode
        // the server typically returns 0.0.0.0/0, which would match the outer UDP
        // packets going to the peer itself, producing a routing loop (black hole).
        // Mirrors wg-quick's behavior of excluding the endpoint from routes. No-op
        // when the peer IP isn't covered by any allowed_ip (e.g. split mode).
        match vpn.ip.parse::<std::net::IpAddr>() {
            Ok(peer_ip) => {
                let peer_cidr = match peer_ip {
                    std::net::IpAddr::V4(_) => format!("{}/32", peer_ip),
                    std::net::IpAddr::V6(_) => format!("{}/128", peer_ip),
                };
                let before = allowed_ips.len();
                let mut carved = Vec::with_capacity(allowed_ips.len());
                for a in &allowed_ips {
                    carved.extend(crate::utils::subtract_cidr_from_cidr(a, &peer_cidr));
                }
                if carved.len() != before {
                    log::info!(
                        "auto-carved peer endpoint {} out of allowed_ips: {} -> {} entries",
                        peer_cidr,
                        before,
                        carved.len()
                    );
                }
                allowed_ips = carved;
            }
            Err(e) => {
                log::warn!(
                    "could not parse vpn.ip {:?} as IP, skipping peer-IP carve-out: {}",
                    vpn.ip,
                    e
                );
            }
        }
        log::info!(
            "final allowed_ips ({} entries): {:?}",
            allowed_ips.len(),
            allowed_ips
        );
        let auto_setup_routes = self.conf.auto_setup_routes.unwrap_or(true);
        let routes = if auto_setup_routes {
            allowed_ips.clone()
        } else {
            log::info!("auto_setup_routes is disabled, skip setting routes");
            Vec::new()
        };

        // corplink config
        let wg_conf = WgConf {
            address,
            address6,
            peer_address: vpn_addr,
            mtu,
            public_key,
            private_key,
            peer_key,
            allowed_ips,
            routes,
            dns,
            // `force_protocol`, when set, overrides the server-advertised `protocol_mode`
            vpn_ip,
            protocol: match self.conf.force_protocol.as_deref() {
                Some(p) if p.eq_ignore_ascii_case("udp") => 0,
                Some(p) if p.eq_ignore_ascii_case("tcp") => 1,
                _ => match vpn.protocol_mode {
                    // tcp
                    1 => 1,
                    // udp
                    _ => 0,
                },
            },
        };
        self.vpn_token_refreshed_at = Some(Instant::now());
        Ok(wg_conf)
    }

    pub async fn keep_alive_vpn(&mut self, conf: &WgConf, interval: u64) {
        loop {
            log::info!("keep alive");
            let needs_token_refresh = self
                .vpn_token_refreshed_at
                .map(|at| at.elapsed() >= VPN_TOKEN_REFRESH_INTERVAL)
                .unwrap_or(true);
            if needs_token_refresh {
                match self.refresh_vpn_token().await {
                    Ok(()) => log::info!("refreshed VPN token"),
                    Err(err) => {
                        // 续期是预防性操作；短暂失败时仍尝试数据面心跳。
                        log::warn!("failed to refresh VPN token: {err}");
                    }
                }
            }
            let report_result = match self.report_vpn_status(conf).await {
                Err(err)
                    if err
                        .downcast_ref::<VpnReportRejected>()
                        .is_some_and(|rejected| rejected.code == VPN_REPORT_AUTH_REJECTED_CODE) =>
                {
                    log::warn!(
                        "VPN report authentication rejected (code {}), refreshing token and retrying once",
                        VPN_REPORT_AUTH_REJECTED_CODE
                    );
                    let recovery = self.recover_vpn_report_auth(conf).await;
                    if recovery.is_ok() {
                        log::info!("VPN report authentication recovered after token resync");
                    }
                    recovery
                }
                result => result,
            };
            match report_result {
                Ok(_) => (),
                Err(err) => {
                    log::warn!("keep alive error: {}", err);
                    return;
                }
            }
            tokio::time::sleep(Duration::from_secs(interval)).await;
        }
    }

    fn vpn_report_body(&self, conf: &WgConf, report_type: &str) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("ip".to_string(), json!(&conf.vpn_ip));
        m.insert("public_key".to_string(), json!(conf.public_key));
        m.insert(
            "mode".to_string(),
            json!(match self.conf.route_mode.clone().unwrap_or_default() {
                crate::config::RouteMode::Split => "Split",
                crate::config::RouteMode::Full => "Full",
            }),
        );
        m.insert("type".to_string(), json!(report_type));
        m
    }

    pub async fn report_vpn_status(&mut self, conf: &WgConf) -> Result<()> {
        let m = self.vpn_report_body(conf, "100");
        let resp = self
            .request::<Map<String, Value>>(ApiName::KeepAliveVPN, Some(m))
            .await?;
        match resp.code {
            0 => Ok(()),
            code => Err(VpnReportRejected {
                code,
                message: resp.message.unwrap_or_default(),
            }
            .into()),
        }
    }

    pub async fn disconnect_vpn(&mut self, wg_conf: &WgConf) -> Result<()> {
        let m = self.vpn_report_body(wg_conf, "101");
        let resp = self
            .request::<Map<String, Value>>(ApiName::DisconnectVPN, Some(m))
            .await?;
        match resp.code {
            0 => Ok(()),
            _ => bail!(format!(
                "failed to fetch peer info with error {}: {}",
                resp.code,
                resp.message.unwrap_or_default()
            )),
        }
    }

    // log out the current terminal, freeing its server-side session/terminal
    // quota (servers cap concurrent terminals, e.g. nankai allows only 3).
    // best-effort: callers treat failures as non-fatal since we're exiting.
    pub async fn logout(&mut self) -> Result<()> {
        let url = self.api_url.get_api_url(&ApiName::Logout);
        let mut req = self.c.get(url);
        // /api/logout validates a csrf-token header (double-submit against the
        // cookie). the token is only known after login, so read it from the
        // cookie store here rather than relying on the default headers.
        if let Some(server) = self.conf.server.as_ref() {
            if let Ok(server_url) = Url::parse(server) {
                if let Some(domain) = server_url.domain().or_else(|| server_url.host_str()) {
                    let token = {
                        let store = self
                            .cookie
                            .lock()
                            .map_err(|e| anyhow!("failed to lock cookie store: {e}"))?;
                        store
                            .get(domain, "/", "csrf-token")
                            .map(|c| c.value().to_string())
                    };
                    if let Some(token) = token {
                        if let Ok(value) = header::HeaderValue::from_str(&token) {
                            req = req.header("csrf-token", value);
                        }
                    }
                }
            }
        }
        // the endpoint replies with a 302 redirect (not JSON), so just confirm
        // the request went through instead of parsing a response body.
        let resp = req.send().await.context("logout request failed")?;
        log::info!("logout (current terminal) status: {}", resp.status());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use cookie::Cookie as RawCookie;
    use cookie_store::CookieStore;
    use reqwest::{ClientBuilder, Url};
    use reqwest_cookie_store::CookieStoreMutex;
    use serde_json::{json, Map, Value};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::{oneshot, Barrier};
    use tokio::time::{sleep, timeout};

    use super::{
        corplink_client_builder, merge_additional_routes, resolve_additional_domains, Client,
        ReqwestCookieStore,
    };
    use crate::api::{ApiName, ApiUrl};
    use crate::config::{Config, WgConf};
    use crate::resp::RespVpnInfo;
    use crate::sign;
    use crate::utils::apply_route_filters;

    async fn start_probe_server(
        barrier: Arc<Barrier>,
        response_delay: Duration,
        session: &'static str,
    ) -> (u16, oneshot::Receiver<String>, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (request_tx, request_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let count = stream.read(&mut buffer).await.unwrap();
                if count == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..count]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            request_tx
                .send(String::from_utf8(request).unwrap())
                .unwrap();

            barrier.wait().await;
            sleep(response_delay).await;
            let body = r#"{"code":0}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nSet-Cookie: vpn_session={session}; Path=/\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        (port, request_rx, task)
    }

    async fn read_request(stream: &mut tokio::net::TcpStream) -> String {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let count = stream.read(&mut buffer).await.unwrap();
            if count == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..count]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        String::from_utf8(request).unwrap()
    }

    fn request_header<'a>(request: &'a str, expected_name: &str) -> Option<&'a str> {
        request.lines().skip(1).find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case(expected_name)
                .then_some(value.trim())
        })
    }

    fn assert_valid_wire_signature(request: &str, company: &str, device_id: &str) -> i64 {
        let request_line = request.lines().next().unwrap();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap();
        let target = parts.next().unwrap();
        let url = Url::parse(&format!("http://localhost{target}")).unwrap();
        let cookie = request_header(request, "cookie").unwrap_or("");
        let csrf = request_header(request, "csrf-token").unwrap_or("");
        let jwt = request_header(request, "jwt-token").unwrap_or("");
        let actual = request_header(request, sign::SIGN_HEADER).expect("missing Sign header");
        let mask = sign::sign_mask_by_path(url.path()).expect("path should be signed");
        let expected = sign::compute_sign(
            company,
            device_id,
            method,
            url.path(),
            url.query().unwrap_or(""),
            b"",
            cookie,
            csrf,
            jwt,
            mask,
        );
        assert_eq!(actual, expected);

        url.query_pairs()
            .find_map(|(name, value)| (name == "timestamp").then(|| value.parse().unwrap()))
            .expect("missing timestamp")
    }

    async fn start_sign_retry_server() -> (
        u16,
        oneshot::Receiver<Vec<String>>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (requests_tx, requests_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            for attempt in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                requests.push(read_request(&mut stream).await);

                let body = if attempt == 0 {
                    r#"{"code":11020001,"message":"expired","data":{"unexpected":true}}"#
                } else {
                    r#"{"code":0,"data":[]}"#
                };
                let server_time = if attempt == 0 {
                    SystemTime::now() + Duration::from_secs(120)
                } else {
                    SystemTime::now()
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nDate: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    httpdate::fmt_http_date(server_time),
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
            requests_tx.send(requests).unwrap();
        });
        (port, requests_rx, task)
    }

    async fn start_report_server() -> (
        u16,
        oneshot::Receiver<Vec<String>>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (requests_tx, requests_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().await.unwrap();
                requests.push(read_request(&mut stream).await);
                let body = r#"{"code":0,"data":{}}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
            requests_tx.send(requests).unwrap();
        });
        (port, requests_rx, task)
    }

    fn vpn_info(port: u16, name: &str) -> RespVpnInfo {
        RespVpnInfo {
            api_port: port,
            vpn_port: port,
            ip: "127.0.0.1".to_string(),
            protocol_mode: 2,
            name: name.to_string(),
            en_name: name.to_string(),
            icon: String::new(),
            id: 0,
            timeout: 0,
        }
    }

    fn test_client() -> Client {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut conf: Config = serde_json::from_value(json!({
            "company_name": "test",
            "username": "test",
            "server": "http://127.0.0.1",
            "interface_name": format!("corplink-probe-test-{unique}"),
            "device_id": "test-device"
        }))
        .unwrap();
        conf.conf_file = Some(
            std::env::temp_dir()
                .join(format!("corplink-probe-test-{unique}.json"))
                .to_string_lossy()
                .into_owned(),
        );
        let client = Client::new(conf).unwrap();
        let server_url = Url::parse("http://127.0.0.1").unwrap();
        client
            .cookie
            .lock()
            .unwrap()
            .insert_raw(&RawCookie::new("csrf-token", "fresh-csrf"), &server_url)
            .unwrap();
        client
    }

    #[tokio::test]
    async fn custom_android_user_agent_is_applied_to_http_clients() {
        let conf: Config = serde_json::from_value(json!({
            "company_name": "test",
            "username": "test",
            "android_profile": {
                "brand": "samsung",
                "model": "SM-S9210",
                "android_release": "14"
            }
        }))
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_request(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            request
        });
        let user_agent = conf.android_user_agent();
        let client = corplink_client_builder(&user_agent).build().unwrap();
        client
            .get(format!("http://{address}"))
            .send()
            .await
            .unwrap();
        let request = server.await.unwrap();

        assert_eq!(
            request_header(&request, "user-agent"),
            Some("CorpLink/3.2.16 (samsung SM-S9210; Android 14; en)")
        );
    }

    #[tokio::test]
    async fn concurrent_default_probe_preserves_order_and_isolates_cookie_state() {
        let barrier = Arc::new(Barrier::new(3));
        let (first_port, first_request, first_task) =
            start_probe_server(Arc::clone(&barrier), Duration::from_millis(75), "first").await;
        let (second_port, second_request, second_task) =
            start_probe_server(Arc::clone(&barrier), Duration::ZERO, "second").await;

        let client = test_client();
        let candidates = vec![
            vpn_info(first_port, "first"),
            vpn_info(second_port, "second"),
        ];

        let selected = timeout(Duration::from_secs(5), async {
            let (selected, _) =
                tokio::join!(client.get_first_available_vpn(candidates), barrier.wait());
            selected
        })
        .await
        .expect("VPN probes did not run concurrently")
        .expect("no VPN was selected");

        assert_eq!(selected.vpn.en_name, "first");
        assert!(selected.set_cookie_headers[0]
            .to_str()
            .unwrap()
            .starts_with("vpn_session=first"));
        let first_request = first_request.await.unwrap().to_ascii_lowercase();
        let second_request = second_request.await.unwrap().to_ascii_lowercase();
        assert_eq!(
            request_header(&first_request, "cookie")
                .and_then(|value| super::cookie_value(value, "device_id")),
            Some("test-device")
        );
        assert_eq!(
            request_header(&second_request, "cookie")
                .and_then(|value| super::cookie_value(value, "device_id")),
            Some("test-device")
        );
        assert!(first_request.contains("user-agent: corplink/3.2.16 "));
        assert!(second_request.contains("user-agent: corplink/3.2.16 "));
        assert!(first_request.contains(
            "get /vpn/ping?os_version_patch=2021-01-05&os=android&app_version=3.2.16&os_version=30&build_number=2008&model=phone&language=en&client_source=feilian&brand=genymotion&timestamp="
        ));
        assert!(second_request.contains(
            "get /vpn/ping?os_version_patch=2021-01-05&os=android&app_version=3.2.16&os_version=30&build_number=2008&model=phone&language=en&client_source=feilian&brand=genymotion&timestamp="
        ));
        assert!(first_request.contains("sign: v1;"));
        assert!(second_request.contains("sign: v1;"));
        assert!(first_request.contains("csrf-token: fresh-csrf"));
        assert!(second_request.contains("csrf-token: fresh-csrf"));

        {
            let cookie_store = client.cookie.lock().unwrap();
            assert!(cookie_store.get("127.0.0.1", "/", "vpn_session").is_none());
        }
        let endpoint_url = client
            .vpn_endpoint_url(&selected.vpn.ip, selected.vpn.api_port)
            .unwrap();
        ReqwestCookieStore::set_cookies(
            client.cookie.as_ref(),
            &mut selected.set_cookie_headers.iter(),
            &endpoint_url,
        );
        {
            let cookie_store = client.cookie.lock().unwrap();
            assert_eq!(
                cookie_store
                    .get("127.0.0.1", "/", "vpn_session")
                    .unwrap()
                    .value(),
                "first"
            );
        }

        first_task.await.unwrap();
        second_task.await.unwrap();
    }

    #[tokio::test]
    async fn concurrent_latency_probe_selects_the_fastest_endpoint() {
        let barrier = Arc::new(Barrier::new(3));
        let (slow_port, slow_request, slow_task) =
            start_probe_server(Arc::clone(&barrier), Duration::from_millis(75), "slow").await;
        let (fast_port, fast_request, fast_task) =
            start_probe_server(Arc::clone(&barrier), Duration::ZERO, "fast").await;
        let client = test_client();
        let candidates = vec![vpn_info(slow_port, "slow"), vpn_info(fast_port, "fast")];

        let selected = timeout(Duration::from_secs(5), async {
            let (selected, _) =
                tokio::join!(client.get_first_vpn_by_latency(candidates), barrier.wait());
            selected
        })
        .await
        .expect("VPN probes did not run concurrently")
        .expect("no VPN was selected");

        assert_eq!(selected.vpn.en_name, "fast");
        assert!(selected.set_cookie_headers[0]
            .to_str()
            .unwrap()
            .starts_with("vpn_session=fast"));
        slow_request.await.unwrap();
        fast_request.await.unwrap();
        slow_task.await.unwrap();
        fast_task.await.unwrap();
    }

    #[tokio::test]
    async fn signed_request_retries_with_current_csrf_and_refreshed_timestamp() {
        let (port, requests_rx, server_task) = start_sign_retry_server().await;
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let server_url = Url::parse(&format!("http://127.0.0.1:{port}")).unwrap();
        let mut conf: Config = serde_json::from_value(json!({
            "company_name": "test",
            "username": "test",
            "server": server_url.as_str().trim_end_matches('/'),
            "interface_name": format!("corplink-sign-test-{unique}"),
            "device_id": "test-device"
        }))
        .unwrap();
        conf.conf_file = Some(
            std::env::temp_dir()
                .join(format!("corplink-sign-test-{unique}.json"))
                .to_string_lossy()
                .into_owned(),
        );
        let mut client = Client::new(conf).unwrap();
        client
            .cookie
            .lock()
            .unwrap()
            .insert_raw(&RawCookie::new("csrf-token", "fresh-csrf"), &server_url)
            .unwrap();

        let response = client
            .request::<Vec<serde_json::Value>>(ApiName::ListVPN, None)
            .await
            .unwrap();
        assert_eq!(response.code, 0);

        let requests = requests_rx.await.unwrap();
        assert_eq!(requests.len(), 2);
        for request in &requests {
            assert_eq!(request_header(request, "csrf-token"), Some("fresh-csrf"));
        }
        let first_timestamp = assert_valid_wire_signature(&requests[0], "test", "test-device");
        let second_timestamp = assert_valid_wire_signature(&requests[1], "test", "test-device");
        assert!(second_timestamp - first_timestamp >= 100);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn signed_probe_retries_with_refreshed_timestamp() {
        let (port, requests_rx, server_task) = start_sign_retry_server().await;
        let client = test_client();

        let selected = client
            .get_first_available_vpn(vec![vpn_info(port, "retry-node")])
            .await
            .expect("probe should retry after a sign timestamp rejection");
        assert_eq!(selected.vpn.en_name, "retry-node");

        let requests = requests_rx.await.unwrap();
        assert_eq!(requests.len(), 2);
        let first_timestamp = assert_valid_wire_signature(&requests[0], "test", "test-device");
        let second_timestamp = assert_valid_wire_signature(&requests[1], "test", "test-device");
        assert!(second_timestamp - first_timestamp >= 100);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn vpn_report_jwt_header_advances_one_successful_request_after_cookie_rotates() {
        let (port, requests_rx, server_task) = start_report_server().await;
        let endpoint_url = Url::parse(&format!("http://127.0.0.1:{port}")).unwrap();
        let mut client = test_client();
        client.api_url.vpn_param.url = endpoint_url.as_str().trim_end_matches('/').to_string();
        {
            let mut store = client.cookie.lock().unwrap();
            store
                .insert_raw(&RawCookie::new("vpn-token", "token-a"), &endpoint_url)
                .unwrap();
        }
        client.vpn_jwt = Some("token-a".to_string());

        client
            .request::<Map<String, Value>>(ApiName::KeepAliveVPN, Some(Map::new()))
            .await
            .unwrap();
        {
            let mut store = client.cookie.lock().unwrap();
            store
                .insert_raw(&RawCookie::new("vpn-token", "token-b"), &endpoint_url)
                .unwrap();
        }
        client
            .request::<Map<String, Value>>(ApiName::KeepAliveVPN, Some(Map::new()))
            .await
            .unwrap();
        client
            .request::<Map<String, Value>>(ApiName::KeepAliveVPN, Some(Map::new()))
            .await
            .unwrap();

        let requests = requests_rx.await.unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(request_header(&requests[0], "jwt-token"), Some("token-a"));
        assert_eq!(
            request_header(&requests[0], "cookie")
                .and_then(|value| super::cookie_value(value, "vpn-token")),
            Some("token-a")
        );
        assert_eq!(request_header(&requests[1], "jwt-token"), Some("token-a"));
        assert_eq!(
            request_header(&requests[1], "cookie")
                .and_then(|value| super::cookie_value(value, "vpn-token")),
            Some("token-b")
        );
        assert_eq!(request_header(&requests[2], "jwt-token"), Some("token-b"));
        assert_eq!(
            request_header(&requests[2], "cookie")
                .and_then(|value| super::cookie_value(value, "vpn-token")),
            Some("token-b")
        );
        for request in &requests {
            assert!(request.starts_with("POST /vpn/report?"));
            assert!(request.contains("&timestamp="));
            assert!(request_header(request, sign::SIGN_HEADER).is_none());
        }
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn vpn_report_auth_recovery_refreshes_and_aligns_data_plane_token() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (requests_tx, requests_rx) = oneshot::channel();
        let server_task = tokio::spawn(async move {
            let mut requests = Vec::new();

            let (mut list_stream, _) = listener.accept().await.unwrap();
            requests.push(read_request(&mut list_stream).await);
            let list_body = r#"{"code":0,"data":[]}"#;
            let list_response = format!(
                "HTTP/1.1 200 OK\r\nSet-Cookie: vpn-token=token-b; Path=/\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{list_body}",
                list_body.len()
            );
            list_stream.write_all(list_response.as_bytes()).await.unwrap();

            let (mut report_stream, _) = listener.accept().await.unwrap();
            requests.push(read_request(&mut report_stream).await);
            let report_body = r#"{"code":0,"data":{}}"#;
            let report_response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{report_body}",
                report_body.len()
            );
            report_stream
                .write_all(report_response.as_bytes())
                .await
                .unwrap();

            requests_tx.send(requests).unwrap();
        });

        let endpoint_url = Url::parse(&format!("http://127.0.0.1:{port}")).unwrap();
        let mut client = test_client();
        client.conf.server = Some(endpoint_url.as_str().trim_end_matches('/').to_string());
        client.api_url = ApiUrl::new(&client.conf).unwrap();
        client.api_url.vpn_param.url = endpoint_url.as_str().trim_end_matches('/').to_string();
        client
            .cookie
            .lock()
            .unwrap()
            .insert_raw(&RawCookie::new("vpn-token", "token-a"), &endpoint_url)
            .unwrap();
        client.vpn_jwt = Some("token-a".to_string());

        let conf = WgConf {
            address: "192.0.2.42/24".to_string(),
            address6: String::new(),
            peer_address: "192.0.2.1:80".to_string(),
            mtu: 1280,
            public_key: "client-public-key".to_string(),
            private_key: "client-private-key".to_string(),
            peer_key: "peer-public-key".to_string(),
            allowed_ips: Vec::new(),
            routes: Vec::new(),
            dns: "192.0.2.53".to_string(),
            vpn_ip: "192.0.2.42".to_string(),
            protocol: 0,
        };
        client.recover_vpn_report_auth(&conf).await.unwrap();

        let requests = requests_rx.await.unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].starts_with("GET /api/vpn/list?"));
        assert!(requests[1].starts_with("POST /vpn/report?"));
        assert_eq!(request_header(&requests[1], "jwt-token"), Some("token-b"));
        assert_eq!(
            request_header(&requests[1], "cookie")
                .and_then(|value| super::cookie_value(value, "vpn-token")),
            Some("token-b")
        );
        server_task.await.unwrap();
    }

    #[test]
    fn vpn_endpoint_urls_use_server_scheme_and_candidate_host() {
        let mut client = test_client();
        client.conf.server = Some("https://127.0.0.1/base?source=config#fragment".to_string());

        let hostname_endpoint = client
            .vpn_endpoint_url("vpn-node.example.com", 8443)
            .unwrap();
        let ipv4_endpoint = client.vpn_endpoint_url("192.0.2.1", 8443).unwrap();
        let ipv6_endpoint = client.prepare_vpn_endpoint("2001:db8::1", 8443).unwrap();

        assert_eq!(
            hostname_endpoint.as_str(),
            "https://vpn-node.example.com:8443/"
        );
        assert_eq!(ipv4_endpoint.as_str(), "https://192.0.2.1:8443/");
        assert_eq!(ipv6_endpoint.as_str(), "https://[2001:db8::1]:8443/");

        // prepare_vpn_endpoint 会把网关域会话 cookie 复制到数据面 IP host，故
        // cookie_header_for(数据面 url) 应能取到 device_id 等 cookie。
        let data_plane_cookie = client.cookie_header_for(&ipv6_endpoint).unwrap();
        assert!(data_plane_cookie.contains("device_id=test-device"));
    }

    #[test]
    fn refreshing_vpn_token_preserves_data_plane_session_identity() {
        let mut client = test_client();
        let gateway_url = Url::parse("http://gateway.example").unwrap();
        let endpoint_url = Url::parse("http://192.0.2.1").unwrap();
        client.conf.server = Some(gateway_url.to_string());

        {
            let mut store = client.cookie.lock().unwrap();
            store
                .insert_raw(&RawCookie::new("session", "control-session"), &gateway_url)
                .unwrap();
            store
                .insert_raw(&RawCookie::new("csrf-token", "control-csrf"), &gateway_url)
                .unwrap();
            store
                .insert_raw(&RawCookie::new("vpn-token", "token-b"), &gateway_url)
                .unwrap();
            store
                .insert_raw(&RawCookie::new("session", "data-session"), &endpoint_url)
                .unwrap();
            store
                .insert_raw(&RawCookie::new("csrf-token", "data-csrf"), &endpoint_url)
                .unwrap();
            store
                .insert_raw(&RawCookie::new("vpn-token", "token-a"), &endpoint_url)
                .unwrap();
        }

        client
            .sync_gateway_vpn_token_to_endpoint(&endpoint_url)
            .unwrap();

        let endpoint_cookie = client.cookie_header_for(&endpoint_url).unwrap();
        assert_eq!(
            super::cookie_value(&endpoint_cookie, "session"),
            Some("data-session")
        );
        assert_eq!(
            super::cookie_value(&endpoint_cookie, "csrf-token"),
            Some("data-csrf")
        );
        assert_eq!(
            super::cookie_value(&endpoint_cookie, "vpn-token"),
            Some("token-b")
        );
    }

    #[test]
    fn vpn_report_body_uses_raw_assigned_ip() {
        let client = test_client();
        let conf = WgConf {
            address: "192.0.2.42/24".to_string(),
            address6: String::new(),
            peer_address: "192.0.2.1:80".to_string(),
            mtu: 1280,
            public_key: "client-public-key".to_string(),
            private_key: "client-private-key".to_string(),
            peer_key: "peer-public-key".to_string(),
            allowed_ips: Vec::new(),
            routes: Vec::new(),
            dns: "192.0.2.53".to_string(),
            vpn_ip: "192.0.2.42".to_string(),
            protocol: 0,
        };

        assert_eq!(
            client.vpn_report_body(&conf, "100"),
            json!({
                "ip": "192.0.2.42",
                "mode": "Split",
                "public_key": "client-public-key",
                "type": "100"
            })
            .as_object()
            .unwrap()
            .clone()
        );
    }

    #[test]
    fn additional_routes_are_validated_deduplicated_and_merged() {
        let routes = merge_additional_routes(
            vec!["10.0.0.0/8".to_string()],
            &[
                "10.0.0.0/8".to_string(),
                "20.205.243.160/28".to_string(),
                "invalid".to_string(),
                "2001:db8::/32".to_string(),
            ],
            false,
        );

        assert_eq!(routes, vec!["10.0.0.0/8", "20.205.243.160/28"]);
    }

    #[test]
    fn additional_ipv6_routes_are_kept_with_an_ipv6_address() {
        let routes = merge_additional_routes(Vec::new(), &["2001:db8::/32".to_string()], true);

        assert_eq!(routes, vec!["2001:db8::/32"]);
    }

    #[test]
    fn additional_routes_are_merged_before_route_filters() {
        let routes = merge_additional_routes(
            vec!["10.0.0.0/8".to_string()],
            &["20.205.243.160/28".to_string()],
            false,
        );
        let allowed = ["20.205.243.160/28".to_string()];

        assert_eq!(
            apply_route_filters(&routes, Some(&allowed), None),
            vec!["20.205.243.160/28"]
        );
    }

    #[tokio::test]
    async fn additional_domains_are_resolved_to_host_routes() {
        let routes = resolve_additional_domains(&["127.0.0.1".to_string()], false).await;

        assert_eq!(routes, vec!["127.0.0.1/32"]);
    }

    /// 构造一个仅用于签名决策测试的最小 Config（不触碰文件/网络）。
    fn sign_test_config(device_id: Option<&str>) -> Config {
        let mut v = json!({
            "company_name": "TestCo",
            "username": "tester",
            "server": "https://example.com",
        });
        if let Some(d) = device_id {
            v["device_id"] = json!(d);
        }
        serde_json::from_value(v).expect("valid test config")
    }

    /// 就地构造一个 Client，跳过 Client::new 的 cookie 文件加载逻辑。
    fn sign_test_client(conf: Config) -> Client {
        let cookie = Arc::new(CookieStoreMutex::new(CookieStore::default()));
        let c = ClientBuilder::new().build().expect("build reqwest client");
        let api_url = ApiUrl::new(&conf).expect("build api url");
        Client {
            conf,
            cookie,
            probe_client: c.clone(),
            c,
            api_url,
            date_offset_sec: 0,
            vpn_jwt: None,
            vpn_token_refreshed_at: None,
        }
    }

    #[test]
    fn build_sign_header_skips_unsigned_path() {
        let client = sign_test_client(sign_test_config(Some("dev-123")));
        let url = Url::parse("https://example.com/api/other").unwrap();
        let out = client
            .build_sign_header("GET", &url, b"")
            .expect("build_sign_header ok");
        assert!(out.is_none(), "unsigned path must not produce a Sign header");
    }

    #[test]
    fn build_sign_header_signs_known_path() {
        let client = sign_test_client(sign_test_config(Some("dev-123")));
        let url = Url::parse("https://example.com/api/vpn/list").unwrap();
        let (name, value) = client
            .build_sign_header("GET", &url, b"")
            .expect("build_sign_header ok")
            .expect("signed path should produce a header");
        assert_eq!(name, sign::SIGN_HEADER);
        assert!(value.starts_with("v1;"), "unexpected sign value: {value}");
    }

    #[test]
    fn build_sign_header_requires_device_id() {
        let client = sign_test_client(sign_test_config(None));
        let url = Url::parse("https://example.com/api/vpn/list").unwrap();
        let err = client
            .build_sign_header("GET", &url, b"")
            .expect_err("missing device_id must be an error");
        assert!(
            err.to_string().contains("device_id"),
            "unexpected error: {err}"
        );
    }
}
