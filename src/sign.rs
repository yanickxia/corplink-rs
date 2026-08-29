//! 飞连（CorpLink）请求签名算法（HKDF-SHA256 派生密钥 + HMAC-SHA256）。
//!
//! canonical 构造与社区 Linux 客户端对齐：
//! `canonical = method ++ path ++ query ++ bodyHash ++ cookieStr ++ csrf`——**直接拼接、无分隔符**，
//! bodyHash 为原始 32 字节 sha256(body)，空 body 时整段省略。密钥派生沿用 Go 二进制逆向所得。
//! 本模块为纯函数、无 IO，可离线单测。

use base64::engine::general_purpose::STANDARD as base64;
use base64::Engine;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// HKDF 的输入密钥材料（IKM），硬编码常量。
pub(crate) const IKM: &[u8] = b"TOK@@AoNfRIX+3bla%";
/// 最终签名值前缀。
pub(crate) const PREFIX: &str = "v1;";
/// 签名写入的 HTTP 头名。
pub const SIGN_HEADER: &str = "Sign";
/// body 的 sha256 原始 32 字节。空 body 时调用方不纳入 canonical（见 build_canonical）。
pub(crate) fn body_hash(body: &[u8]) -> [u8; 32] {
    Sha256::digest(body).into()
}

/// HKDF-SHA256 派生 32 字节签名密钥。
/// salt=None（等价 RFC5869 的 HashLen 个 0 字节，与 Go x/crypto/hkdf 的 nil 一致）。
/// info = company + "|" + device_id。
pub(crate) fn derive_sign_key(company: &str, device_id: &str) -> [u8; 32] {
    let info = format!("{}|{}", company, device_id);
    let hk = Hkdf::<Sha256>::new(None, IKM);
    let mut okm = [0u8; 32];
    hk.expand(info.as_bytes(), &mut okm)
        .expect("32 is a valid HKDF-SHA256 output length");
    okm
}

/// 按 mask 的位选取字段并**直接拼接**（无分隔符）成字节序列。
/// 位→字段：1=method, 2=urlPath, 3=query, 4=bodyHash, 5=cookieStr, 7=csrf, 9=jwtToken。
/// 拼接顺序固定为 method, urlPath, query, bodyHash, cookieStr, csrf, jwtToken。
/// bodyHash 为原始 32 字节 sha256(body)；`body_hash=None`（空 body）时该段整体省略，
/// 即便 mask 的 bit4 置位也不写入——与真实客户端一致。
/// jwt（bit9）用于数据面端点（/vpn/conn 等 mask=0x21e），取自 `vpn-token` cookie，
/// 替代 cookieStr/csrf 参与签名。
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_canonical(
    mask: u64,
    method: &str,
    url_path: &str,
    query: &str,
    body_hash: Option<&[u8]>,
    cookie_str: &str,
    csrf: &str,
    jwt: &str,
) -> Vec<u8> {
    let mut out = Vec::new();
    if (mask >> 1) & 1 == 1 {
        out.extend_from_slice(method.as_bytes());
    }
    if (mask >> 2) & 1 == 1 {
        out.extend_from_slice(url_path.as_bytes());
    }
    if (mask >> 3) & 1 == 1 {
        out.extend_from_slice(query.as_bytes());
    }
    if (mask >> 4) & 1 == 1 {
        if let Some(bh) = body_hash {
            out.extend_from_slice(bh);
        }
    }
    if (mask >> 5) & 1 == 1 {
        out.extend_from_slice(cookie_str.as_bytes());
    }
    if (mask >> 7) & 1 == 1 {
        out.extend_from_slice(csrf.as_bytes());
    }
    if (mask >> 9) & 1 == 1 {
        out.extend_from_slice(jwt.as_bytes());
    }
    out
}

/// 标准 LEB128 无符号 varint，追加到 out。
fn put_uvarint(out: &mut Vec<u8>, mut n: u64) {
    while n >= 0x80 {
        out.push((n as u8 & 0x7f) | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
}

/// 序列化签名 payload（protobuf 手写）：
/// field1 varint=1；field3 varint=mask；field4 bytes=digest。
/// 字节结构：08 01 18 <varint(mask)> 22 <varint(len)> <digest>。
pub(crate) fn encode_sign_payload(mask: u64, digest: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + digest.len());
    out.push(0x08);
    out.push(0x01); // field1 = 1
    out.push(0x18);
    put_uvarint(&mut out, mask); // field3 = mask
    out.push(0x22);
    put_uvarint(&mut out, digest.len() as u64);
    out.extend_from_slice(digest); // field4 = digest
    out
}

type HmacSha256 = Hmac<Sha256>;

/// 计算完整 `Sign` 头的值。
/// `jwt` 用于数据面端点（mask bit9），取自 `vpn-token` cookie；网关端点可传 ""。
#[allow(clippy::too_many_arguments)]
pub(crate) fn compute_sign(
    company: &str,
    device_id: &str,
    method: &str,
    url_path: &str,
    query: &str,
    body: &[u8],
    cookie_str: &str,
    csrf: &str,
    jwt: &str,
    mask: u64,
) -> String {
    let key = derive_sign_key(company, device_id);
    // bodyHash 为原始 32 字节 sha256(body)；空 body 时不纳入 canonical。
    let bh = if body.is_empty() {
        None
    } else {
        Some(body_hash(body))
    };
    let canonical = build_canonical(
        mask,
        method,
        url_path,
        query,
        bh.as_ref().map(|b| b.as_slice()),
        cookie_str,
        csrf,
        jwt,
    );

    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC accepts any key length");
    mac.update(&canonical);
    let digest = mac.finalize().into_bytes(); // 32 字节

    let payload = encode_sign_payload(mask, &digest);
    format!("{}{}", PREFIX, base64.encode(payload))
}

/// 返回该 path 对应的签名 mask；不在表中的 path 不签名（返回 None）。
/// 社区 Linux 客户端只签名节点列表和连接请求：列表用 0x1fe（含
/// cookie+csrf），/vpn/conn 用 0x21e（method/path/query/bodyHash/vpn-token）。
/// /vpn/ping 和 /vpn/report 都不签名。
pub(crate) fn sign_mask_by_path(path: &str) -> Option<u64> {
    match path {
        "/api/vpn/list" => Some(0x1fe),
        "/vpn/conn" => Some(0x21e),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_body_hash() {
        // 原始 32 字节 sha256
        assert_eq!(
            body_hash(b"").to_vec(),
            hex_bytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(
            body_hash(b"hello").to_vec(),
            hex_bytes("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        );
    }

    #[test]
    fn test_sign_mask_by_path() {
        assert_eq!(sign_mask_by_path("/api/vpn/list"), Some(0x1fe));
        assert_eq!(sign_mask_by_path("/vpn/ping"), None);
        assert_eq!(sign_mask_by_path("/vpn/conn"), Some(0x21e));
        assert_eq!(sign_mask_by_path("/vpn/report"), None);
        assert_eq!(sign_mask_by_path("/api/device/report"), None);
        assert_eq!(sign_mask_by_path("/api/emgr/device/report"), None);
        assert_eq!(sign_mask_by_path("/api/login"), None);
        assert_eq!(sign_mask_by_path("/api/vpn/list/"), None); // 精确匹配，尾斜杠不命中
    }

    #[test]
    fn test_derive_sign_key() {
        let key = derive_sign_key("acme", "deadbeef");
        let hex: String = key.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            hex,
            "eb61cd3d5938723254c0cafa51de62e37c74be88bcfc4c1743bc7ca51d568556"
        );
    }

    #[test]
    fn test_derive_sign_key_preserves_company_case() {
        assert_ne!(
            derive_sign_key("ACME", "deadbeef"),
            derive_sign_key("acme", "deadbeef")
        );
    }

    #[test]
    fn test_build_canonical_1fe_direct_concat_no_separator() {
        // 0x1fe 含全部 6 字段，直接拼接、无分隔符；GET（空 body）无 bodyHash 段
        let c = build_canonical(
            0x1fe,
            "GET",
            "/api/vpn/list",
            "os=Android&os_version=2&timestamp=1700000000",
            None, // 空 body → 省略 bodyHash
            "csrf-token=abc; device_id=deadbeef",
            "abc",
            "", // jwt 不参与（mask 无 bit9）
        );
        assert_eq!(
            c,
            b"GET/api/vpn/listos=Android&os_version=2&timestamp=1700000000\
csrf-token=abc; device_id=deadbeefabc"
                .to_vec()
        );
    }

    #[test]
    fn test_build_canonical_1fe_with_body_hash_raw_bytes() {
        // 非空 body：bodyHash 为原始 32 字节，紧跟 query 之后、cookie 之前
        let bh = body_hash(b"{}");
        let c = build_canonical(
            0x1fe,
            "POST",
            "/api/device/report",
            "os=Android&timestamp=1700000000",
            Some(&bh),
            "csrf-token=abc",
            "abc",
            "",
        );
        let mut expect = Vec::new();
        expect.extend_from_slice(b"POST/api/device/reportos=Android&timestamp=1700000000");
        expect.extend_from_slice(&bh); // 原始字节，不是 hex
        expect.extend_from_slice(b"csrf-token=abcabc");
        assert_eq!(c, expect);
    }

    #[test]
    fn test_build_canonical_21e_uses_jwt_not_cookie_csrf() {
        // 0x21e (bits 1,2,3,4,9)：method/urlPath/query/bodyHash/jwt，不含 cookieStr/csrf
        let bh = body_hash(b"{}");
        let c = build_canonical(
            0x21e,
            "POST",
            "/vpn/conn",
            "os=Android&timestamp=1700000000",
            Some(&bh),
            "csrf-token=abc; device_id=deadbeef", // 不应出现在 canonical
            "abc",                                // 不应出现在 canonical
            "jwt.header.value",
        );
        let mut expect = Vec::new();
        expect.extend_from_slice(b"POST/vpn/connos=Android&timestamp=1700000000");
        expect.extend_from_slice(&bh);
        expect.extend_from_slice(b"jwt.header.value");
        assert_eq!(c, expect);
    }

    #[test]
    fn test_encode_sign_payload_1fe() {
        let out = encode_sign_payload(0x1fe, &[0xabu8; 32]);
        let hex: String = out.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            hex,
            "080118fe032220abababababababababababababababababababababababababababababababab"
        );
    }

    #[test]
    fn test_encode_sign_payload_21e() {
        let out = encode_sign_payload(0x21e, &[0x11u8; 32]);
        let hex: String = out.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            hex,
            "0801189e0422201111111111111111111111111111111111111111111111111111111111111111"
        );
    }

    // ---- 安卓请求形态回归向量（已脱敏）----
    // 字段组合来自真机抓包验证，所有租户、设备、Cookie 和 token 均为合成值。
    const TEST_COMPANY: &str = "example-corp";
    const TEST_DEVICE_ID: &str = "test-device-0123456789abcdef";
    const TEST_CSRF: &str = "test-csrf-token";
    const TEST_JWT: &str = "test-vpn-token";

    #[test]
    fn test_compute_sign_android_shape_info_me() {
        let query = "os_version_patch=2021-01-05&os=Android&app_version=3.2.16&os_version=30&build_number=2008&model=Phone&language=en&client_source=FeiLian&brand=Genymotion&timestamp=1700000100";
        let cookie = "session=test-session-a; csrf-token=test-csrf-token; vpn-token=test-vpn-token; device_id=test-device-0123456789abcdef; device_name=Android+Test";
        let sign = compute_sign(
            TEST_COMPANY,
            TEST_DEVICE_ID,
            "GET",
            "/api/info/me",
            query,
            b"",
            cookie,
            TEST_CSRF,
            "",
            0x1fe,
        );
        assert_eq!(
            sign,
            "v1;CAEY/gMiIOaz6fhjpHsFDd9H8WsBPvsH9kClGNzQIElLDAhGb65s"
        );
    }

    #[test]
    fn test_compute_sign_android_shape_vpn_list() {
        let query = "os_version_patch=2021-01-05&os=Android&app_version=3.2.16&os_version=30&build_number=2008&model=Phone&language=en&client_source=FeiLian&brand=Genymotion&timestamp=1700000101";
        let cookie = "session=test-session-b; csrf-token=test-csrf-token; vpn-token=test-vpn-token; device_id=test-device-0123456789abcdef; device_name=Android+Test";
        let sign = compute_sign(
            TEST_COMPANY,
            TEST_DEVICE_ID,
            "GET",
            "/api/vpn/list",
            query,
            b"",
            cookie,
            TEST_CSRF,
            "",
            0x1fe,
        );
        assert_eq!(
            sign,
            "v1;CAEY/gMiIKfTp+9aO9kfIe+4+j//gFuHYic4kcaQkteHjH7Pi+py"
        );
    }

    // ---- 安卓 /vpn/conn 形态回归向量（数据面, mask 0x21e, bit9=jwt）----
    // 使用两组不同的合成 body/timestamp，交叉验证签名规则的泛化性。
    // canonical = method + path + query + sha256(body) + jwt_token（无 cookie/csrf）。

    #[test]
    fn test_compute_sign_android_shape_vpn_conn_1() {
        let query = "os_version_patch=2021-01-05&os=Android&app_version=3.2.16&os_version=30&build_number=2008&model=Phone&language=en&client_source=FeiLian&brand=Genymotion&timestamp=1700000102";
        let body = br#"{"mode":"Split","public_key":"test-public-key-1","otp":"000001","export_id":0,"not_auto":false}"#;
        let sign = compute_sign(
            TEST_COMPANY,
            TEST_DEVICE_ID,
            "POST",
            "/vpn/conn",
            query,
            body,
            "",   // cookie 不参与（0x21e 无 bit5）
            "",   // csrf 不参与（0x21e 无 bit7）
            TEST_JWT,
            0x21e,
        );
        assert_eq!(
            sign,
            "v1;CAEYngQiIIBY7RGBceJ9ROtDQvS7uYrw+pbWymmOAKMY+VTilFAa"
        );
    }

    #[test]
    fn test_compute_sign_android_shape_vpn_conn_2() {
        let query = "os_version_patch=2021-01-05&os=Android&app_version=3.2.16&os_version=30&build_number=2008&model=Phone&language=en&client_source=FeiLian&brand=Genymotion&timestamp=1700000103";
        let body = br#"{"mode":"Split","public_key":"test-public-key-2","otp":"000002","export_id":0,"not_auto":false}"#;
        let sign = compute_sign(
            TEST_COMPANY,
            TEST_DEVICE_ID,
            "POST",
            "/vpn/conn",
            query,
            body,
            "",
            "",
            TEST_JWT,
            0x21e,
        );
        assert_eq!(
            sign,
            "v1;CAEYngQiIEulXrVpNcI2v1ZGbesHWgsdkdmMhMNF/10IoVUlG3rk"
        );
    }

    /// 把偶数长度的小写 hex 串转成字节，供测试断言用。
    fn hex_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
