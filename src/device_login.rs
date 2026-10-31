//! Android device authentication helpers. VPN requests keep their existing profile.
use anyhow::{bail, Context, Result};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use rand::{rngs::OsRng, RngCore};
use reqwest::Url;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::resp::{RespDeviceLogin, RespTpsLoginMethod};

pub const USER_AGENT: &str =
    "CorpLink/3.3.23 (AndroidAndroid SDK built for arm64; Android 8.1.0; en)";

pub fn apply_profile(url: &mut Url, timestamp: i64) {
    url.set_query(None);
    url.query_pairs_mut()
        .extend_pairs([
            ("os_version_patch", "2018-01-05"),
            ("os", "Android"),
            ("app_version", "3.3.23"),
            ("os_version", "27"),
            ("build_number", "2442"),
            ("model", "Android SDK built for arm64"),
            ("language", "en"),
            ("client_source", "FeiLian"),
            ("brand", "Android"),
        ])
        .append_pair("timestamp", &timestamp.to_string());
}

pub struct DeviceAuthorization {
    pub method: RespTpsLoginMethod,
    pub verifier: String,
}

pub fn new_pkce() -> (String, String) {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    // Match Android's base64 verifier and SHA256/base64url challenge exactly.
    let verifier = STANDARD.encode(bytes);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

impl DeviceAuthorization {
    pub fn callback_body(&self, server: &str, input: &str) -> Result<Map<String, Value>> {
        // Do not include authorization codes in parser errors or logs.
        let url =
            Url::parse(input.trim()).map_err(|_| anyhow::anyhow!("请输入完整的登录回调地址"))?;
        let gateway = Url::parse(server).context("invalid server URL")?;
        let app_callback = url.scheme() == "corplink"
            && url.host_str() == Some("login")
            && url.path() == "/callback";
        let web_callback = url.origin() == gateway.origin()
            && url.path() == "/multiple-pages/device-callback.html";
        if !(app_callback || web_callback) || !url.username().is_empty() || url.password().is_some()
        {
            bail!("请粘贴本次飞连授权完成后的设备回调地址，而不是 SSO 登录页地址");
        }
        let mut body = Map::new();
        for name in ["alias_key", "code", "state"] {
            let values: Vec<_> = url.query_pairs().filter(|(key, _)| key == name).collect();
            if values.len() != 1 || values[0].1.is_empty() {
                bail!("登录回调地址缺少或重复字段 {name}");
            }
            body.insert(name.to_string(), json!(values[0].1));
        }
        if body["alias_key"].as_str() != Some(&self.method.alias_key) {
            bail!("回调的登录方式与本次授权不一致，请使用本次打开的授权页面");
        }
        // SSO/OIDC links expose their state directly. Other providers may nest it;
        // the server still validates the callback state and PKCE verifier there.
        let login_url = Url::parse(&self.method.login_url).context("invalid login URL")?;
        if let Some((_, state)) = login_url.query_pairs().find(|(key, _)| key == "state") {
            if body["state"].as_str() != Some(state.as_ref()) {
                bail!("回调不属于本次登录，请使用本次打开的授权页面");
            }
        }
        body.insert("code_verifier".to_string(), json!(self.verifier));
        Ok(body)
    }
}

pub fn ensure_complete(data: &RespDeviceLogin) -> Result<()> {
    if data.result != "success" {
        bail!("登录尚未成功，请重新运行登录");
    }
    match data.next.as_ref().map(|next| next.action.as_str()) {
        None | Some("") | Some("GoToLink") => Ok(()),
        Some(action) => bail!("登录还需要完成 {action}；暂不支持该步骤，未保存为已登录状态"),
    }
}

pub fn mfa_body(kind: &str, code: Option<&str>) -> Map<String, Value> {
    let mut body = Map::new();
    body.insert("login_scene".to_string(), json!("feilian"));
    body.insert("mfa_type".to_string(), json!(kind));
    // For TPS login, the session identifies the account (Android sends "").
    body.insert("account".to_string(), json!(""));
    if let Some(code) = code {
        body.insert("code".to_string(), json!(code));
    }
    body
}

pub fn read_input(prompt: &str) -> Result<String> {
    use std::io::{self, Write};
    if crate::login_ui::enabled() {
        crate::login_ui::emit(json!({
            "event": "prompt",
            "kind": if prompt.contains("回调") { "callback" } else { "code" },
            "prompt": prompt,
        }));
    } else {
        println!("{prompt}");
    }
    io::stdout().flush()?;
    let mut line = String::new();
    if io::stdin().read_line(&mut line)? == 0 {
        bail!("标准输入已关闭，无法继续交互登录");
    }
    Ok(line.trim().to_string())
}

pub fn open_browser(url: &str) {
    // Commands receive the URL as an argument, never as shell source.
    #[cfg(target_os = "macos")]
    let result = std::process::Command::new("open").arg(url).status();
    #[cfg(target_os = "linux")]
    let result = std::process::Command::new("xdg-open").arg(url).status();
    #[cfg(target_os = "windows")]
    let result = std::process::Command::new("rundll32.exe")
        .arg("url.dll,FileProtocolHandler")
        .arg(url)
        .status();
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let result: std::io::Result<std::process::ExitStatus> =
        Err(std::io::ErrorKind::Unsupported.into());
    if !matches!(result, Ok(status) if status.success()) {
        eprintln!("未能自动打开浏览器，请手动打开上方链接。");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authorization() -> DeviceAuthorization {
        DeviceAuthorization {
            method: RespTpsLoginMethod {
                alias: "bytedance_sso".into(),
                alias_key: "bytedance_sso".into(),
                login_url: "https://sso.example.com/authorize?state=this-attempt".into(),
                token: String::new(),
            },
            verifier: "test-verifier".into(),
        }
    }

    #[test]
    fn parses_android_and_browser_callbacks_without_losing_encoded_code() {
        for prefix in [
            "corplink://login/callback",
            "https://vpn.example.com/multiple-pages/device-callback.html",
        ] {
            let body = authorization().callback_body("https://vpn.example.com",
                &format!("{prefix}?alias_key=bytedance_sso&code=a%2Bb%2Fc%3D&state=this-attempt&schema=corplink://login/callback")).unwrap();
            assert_eq!(body["code"], "a+b/c=");
            assert_eq!(body["code_verifier"], "test-verifier");
        }
    }

    #[test]
    fn refuses_wrong_origin_alias_state_and_duplicate_callback_parameters() {
        for input in [
            "https://evil.example/multiple-pages/device-callback.html?alias_key=bytedance_sso&code=secret&state=this-attempt",
            "https://vpn.example.com/not-a-callback?alias_key=bytedance_sso&code=secret&state=this-attempt",
            "corplink://login/callback?alias_key=other&code=secret&state=this-attempt",
            "corplink://login/callback?alias_key=bytedance_sso&code=secret&state=old-attempt",
            "corplink://login/callback?alias_key=bytedance_sso&code=secret&code=other&state=this-attempt",
            "corplink://login/callback?alias_key=bytedance_sso&state=this-attempt",
        ] {
            let error = authorization().callback_body("https://vpn.example.com", input).unwrap_err().to_string();
            assert!(!error.contains("secret"));
        }
    }

    #[test]
    fn mfa_or_unhandled_actions_never_count_as_finished_login() {
        for action in ["2FA", "OpenWebview", "ResetPassword", "unknown"] {
            let data: RespDeviceLogin =
                serde_json::from_value(json!({"result":"success","next":{"action":action}}))
                    .unwrap();
            assert!(ensure_complete(&data).is_err());
        }
        let success: RespDeviceLogin =
            serde_json::from_value(json!({"result":"success","next":{"action":"GoToLink"}}))
                .unwrap();
        assert!(ensure_complete(&success).is_ok());
        let failure: RespDeviceLogin = serde_json::from_value(json!({"result":"failure"})).unwrap();
        assert!(ensure_complete(&failure).is_err());
    }

    #[test]
    fn pkce_is_fresh_and_matches_android_encoding() {
        let (verifier, challenge) = new_pkce();
        assert_eq!(STANDARD.decode(&verifier).unwrap().len(), 32);
        assert_eq!(
            URL_SAFE_NO_PAD.decode(challenge).unwrap(),
            Sha256::digest(verifier.as_bytes()).to_vec()
        );
        assert_ne!(verifier, new_pkce().0);
    }
}
