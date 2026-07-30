use std::collections::HashMap;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::config::Config;
use crate::template::Template;

pub const URL_GET_COMPANY: &str = "https://corplink.volcengine.cn/api/match";
pub(crate) const CORPLINK_APP_VERSION: &str = "201000";
pub(crate) const CORPLINK_ANDROID_APP_VERSION: &str = "3.2.16";

const URL_GET_LOGIN_METHOD: &str = "{{url}}/api/login/setting?os={{os}}&os_version={{version}}";
const URL_GET_TPS_LOGIN_METHOD: &str = "{{url}}/api/tpslogin/link?os={{os}}&os_version={{version}}";
const URL_GET_TPS_TOKEN_CHECK: &str =
    "{{url}}/api/tpslogin/token/check?os={{os}}&os_version={{version}}";
const URL_GET_CORPLINK_LOGIN_METHOD: &str = "{{url}}/api/lookup?os={{os}}&os_version={{version}}";
const URL_REQUEST_CODE: &str = "{{url}}/api/login/code/send?os={{os}}&os_version={{version}}";
const URL_VERIFY_CODE: &str = "{{url}}/api/login/code/verify?os={{os}}&os_version={{version}}";
const URL_LOGIN_PASSWORD: &str = "{{url}}/api/login?os={{os}}&os_version={{version}}";
const URL_LOGIN_PASSWORD_V1: &str =
    "{{url}}/api/v1/login?os={{os}}&os_version={{version}}&client_source=FeiLian";
const URL_LIST_VPN: &str = "{{url}}/api/vpn/list?os={{os}}&os_version={{version}}";

// 数据面参数需和当前安卓客户端逐项、逐序一致；/vpn/conn 的 query
// 还会参与签名计算，心跳也应保持同一份客户端身份。
const URL_PING_VPN_HOST: &str = "{{url}}/vpn/ping?os_version_patch={{os_version_patch}}&os={{os}}&app_version={{app_version}}&os_version={{os_version}}&build_number={{build_number}}&model={{model}}&language={{language}}&client_source={{client_source}}&brand={{brand}}";
const URL_FETCH_PEER_INFO: &str = "{{url}}/vpn/conn?os_version_patch={{os_version_patch}}&os={{os}}&app_version={{app_version}}&os_version={{os_version}}&build_number={{build_number}}&model={{model}}&language={{language}}&client_source={{client_source}}&brand={{brand}}";
const URL_OPERATE_VPN: &str = "{{url}}/vpn/report?os_version_patch={{os_version_patch}}&os={{os}}&app_version={{app_version}}&os_version={{os_version}}&build_number={{build_number}}&model={{model}}&language={{language}}&client_source={{client_source}}&brand={{brand}}";
const URL_OTP: &str = "{{url}}/api/v2/p/otp?os={{os}}&os_version={{version}}";
// log out the current terminal so it frees the server-side session/terminal
// quota. logout_all=false only signs out this device. responds with a 302.
const URL_LOGOUT: &str =
    "{{url}}/api/logout?os={{os}}&os_version={{version}}&logout_all=false";

#[derive(Clone, Hash, Eq, PartialEq, Debug)]
pub enum ApiName {
    LoginMethod,
    TpsLoginMethod,
    TpsTokenCheck,
    CorplinkLoginMethod,
    RequestEmailCode,
    LoginPassword,
    LoginPasswordV1,
    LoginEmail,
    ListVPN,

    PingVPN,
    ConnectVPN,
    KeepAliveVPN,
    DisconnectVPN,
    Otp,
    Logout,
}

#[derive(Clone, Serialize)]
struct UserUrlParam {
    url: String,
    os: String,
    version: String,
    app_version: String,
}

#[derive(Clone, Serialize)]
pub struct VpnUrlParam {
    pub url: String,
    os: String,
    os_version_patch: String,
    app_version: String,
    os_version: String,
    build_number: String,
    model: String,
    language: String,
    client_source: String,
    brand: String,
}

#[derive(Clone)]
pub struct ApiUrl {
    user_param: UserUrlParam,
    pub vpn_param: VpnUrlParam,
    api_template: HashMap<ApiName, Template>,
}

impl ApiUrl {
    pub fn new(conf: &Config) -> Result<ApiUrl> {
        let os = "Android".to_string();
        let version = "2".to_string();
        let mut api_template = HashMap::new();

        api_template.insert(ApiName::LoginMethod, Template::new(URL_GET_LOGIN_METHOD));
        api_template.insert(
            ApiName::TpsLoginMethod,
            Template::new(URL_GET_TPS_LOGIN_METHOD),
        );
        api_template.insert(
            ApiName::TpsTokenCheck,
            Template::new(URL_GET_TPS_TOKEN_CHECK),
        );
        api_template.insert(
            ApiName::CorplinkLoginMethod,
            Template::new(URL_GET_CORPLINK_LOGIN_METHOD),
        );
        api_template.insert(ApiName::RequestEmailCode, Template::new(URL_REQUEST_CODE));
        api_template.insert(ApiName::LoginEmail, Template::new(URL_VERIFY_CODE));
        api_template.insert(ApiName::LoginPassword, Template::new(URL_LOGIN_PASSWORD));
        api_template.insert(
            ApiName::LoginPasswordV1,
            Template::new(URL_LOGIN_PASSWORD_V1),
        );
        api_template.insert(ApiName::ListVPN, Template::new(URL_LIST_VPN));
        api_template.insert(ApiName::PingVPN, Template::new(URL_PING_VPN_HOST));
        api_template.insert(ApiName::ConnectVPN, Template::new(URL_FETCH_PEER_INFO));
        api_template.insert(ApiName::KeepAliveVPN, Template::new(URL_OPERATE_VPN));
        api_template.insert(ApiName::DisconnectVPN, Template::new(URL_OPERATE_VPN));
        api_template.insert(ApiName::Otp, Template::new(URL_OTP));
        api_template.insert(ApiName::Logout, Template::new(URL_LOGOUT));

        Ok(ApiUrl {
            user_param: UserUrlParam {
                url: conf
                    .server
                    .clone()
                    .context("server url missing in config")?,
                os: os.clone(),
                version: version.clone(),
                app_version: CORPLINK_APP_VERSION.to_string(),
            },
            vpn_param: VpnUrlParam {
                url: "".to_string(),
                os,
                os_version_patch: "2021-01-05".to_string(),
                app_version: CORPLINK_ANDROID_APP_VERSION.to_string(),
                os_version: "30".to_string(),
                build_number: "2008".to_string(),
                model: "Phone".to_string(),
                language: "en".to_string(),
                client_source: "FeiLian".to_string(),
                brand: "Genymotion".to_string(),
            },
            api_template,
        })
    }

    pub fn get_api_url(&self, name: &ApiName) -> String {
        let user_param = &self.user_param;
        let vpn_param = &self.vpn_param;
        match name {
            ApiName::LoginMethod => self.api_template[name].render(user_param),
            ApiName::TpsLoginMethod => self.api_template[name].render(user_param),
            ApiName::TpsTokenCheck => self.api_template[name].render(user_param),
            ApiName::CorplinkLoginMethod => self.api_template[name].render(user_param),
            ApiName::RequestEmailCode => self.api_template[name].render(user_param),
            ApiName::LoginEmail => self.api_template[name].render(user_param),
            ApiName::LoginPassword => self.api_template[name].render(user_param),
            ApiName::LoginPasswordV1 => self.api_template[name].render(user_param),
            ApiName::ListVPN => self.api_template[name].render(user_param),
            ApiName::Otp => self.api_template[name].render(user_param),
            ApiName::Logout => self.api_template[name].render(user_param),

            ApiName::PingVPN => self.api_template[name].render(vpn_param),
            ApiName::ConnectVPN => self.api_template[name].render(vpn_param),
            ApiName::KeepAliveVPN => self.api_template[name].render(vpn_param),
            ApiName::DisconnectVPN => self.api_template[name].render(vpn_param),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn signed_list_vpn_url_uses_legacy_parameter_set() {
        let conf: Config = serde_json::from_value(json!({
            "company_name": "test",
            "username": "test",
            "server": "https://vpn.example.com"
        }))
        .unwrap();

        let api_url = ApiUrl::new(&conf).unwrap();

        assert_eq!(
            api_url.get_api_url(&ApiName::ListVPN),
            "https://vpn.example.com/api/vpn/list?os=Android&os_version=2"
        );
    }

    #[test]
    fn vpn_data_plane_urls_match_current_android_parameter_order() {
        let conf: Config = serde_json::from_value(json!({
            "company_name": "test",
            "username": "test",
            "server": "https://vpn.example.com"
        }))
        .unwrap();
        let mut api_url = ApiUrl::new(&conf).unwrap();
        api_url.vpn_param.url = "https://192.0.2.1:8443".to_string();
        let query = "os_version_patch=2021-01-05&os=Android&app_version=3.2.16&os_version=30&build_number=2008&model=Phone&language=en&client_source=FeiLian&brand=Genymotion";

        assert_eq!(
            api_url.get_api_url(&ApiName::PingVPN),
            format!("https://192.0.2.1:8443/vpn/ping?{query}")
        );
        assert_eq!(
            api_url.get_api_url(&ApiName::ConnectVPN),
            format!("https://192.0.2.1:8443/vpn/conn?{query}")
        );
        assert_eq!(
            api_url.get_api_url(&ApiName::KeepAliveVPN),
            format!("https://192.0.2.1:8443/vpn/report?{query}")
        );
    }
}
