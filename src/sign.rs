//! 飞连（CorpLink）请求签名算法（HKDF-SHA256 派生密钥 + HMAC-SHA256）。
//!
//! 从某 fork 的 Go 二进制字节级逆向而来。
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
/// canonical 字段分隔符。
const SEP: &str = "\n";

/// body 的 sha256 小写十六进制（64 字符）。空 body 返回 sha256("") 的 hex。
pub(crate) fn body_hash_hex(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    // 小写 hex，与 Go 的 hex.EncodeToString 一致
    let mut s = String::with_capacity(64);
    for b in digest.iter() {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// HKDF-SHA256 派生 32 字节签名密钥。
/// salt=None（等价 RFC5869 的 HashLen 个 0 字节，与 Go x/crypto/hkdf 的 nil 一致）。
/// info = company.to_lowercase() + "|" + device_id。
pub(crate) fn derive_sign_key(company: &str, device_id: &str) -> [u8; 32] {
    let info = format!("{}|{}", company.to_lowercase(), device_id);
    let hk = Hkdf::<Sha256>::new(None, IKM);
    let mut okm = [0u8; 32];
    hk.expand(info.as_bytes(), &mut okm)
        .expect("32 is a valid HKDF-SHA256 output length");
    okm
}

/// 按 mask 的位选取字段并用 "\n" 连接。
/// 位→字段：1=method, 2=urlPath, 3=query, 4=bodyHash, 5=cookieStr, 7=csrf。
/// 追加顺序固定为 method, urlPath, query, bodyHash, cookieStr, csrf。
pub(crate) fn build_canonical(
    mask: u64,
    method: &str,
    url_path: &str,
    query: &str,
    body_hash: &str,
    cookie_str: &str,
    csrf: &str,
) -> String {
    let candidates: [(u32, &str); 6] = [
        (1, method),
        (2, url_path),
        (3, query),
        (4, body_hash),
        (5, cookie_str),
        (7, csrf),
    ];
    let parts: Vec<&str> = candidates
        .iter()
        .filter(|(bit, _)| (mask >> bit) & 1 == 1)
        .map(|(_, v)| *v)
        .collect();
    parts.join(SEP)
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
    mask: u64,
) -> String {
    let key = derive_sign_key(company, device_id);
    let body_hash = body_hash_hex(body);
    let canonical = build_canonical(mask, method, url_path, query, &body_hash, cookie_str, csrf);

    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC accepts any key length");
    mac.update(canonical.as_bytes());
    let digest = mac.finalize().into_bytes(); // 32 字节

    let payload = encode_sign_payload(mask, &digest);
    format!("{}{}", PREFIX, base64.encode(payload))
}

/// 返回该 path 对应的签名 mask；不在表中的 path 不签名（返回 None）。
pub(crate) fn sign_mask_by_path(path: &str) -> Option<u64> {
    match path {
        "/api/vpn/list" => Some(0x1fe),
        "/vpn/ping" => Some(0x1fe),
        "/vpn/conn" => Some(0x21e),
        "/vpn/report" => Some(0x21e),
        "/api/device/report" => Some(0x1fe),
        "/api/emgr/device/report" => Some(0x1fe),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_body_hash_hex() {
        assert_eq!(
            body_hash_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            body_hash_hex(b"hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        assert_eq!(
            body_hash_hex(b"{}"),
            "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        );
    }

    #[test]
    fn test_sign_mask_by_path() {
        assert_eq!(sign_mask_by_path("/api/vpn/list"), Some(0x1fe));
        assert_eq!(sign_mask_by_path("/vpn/ping"), Some(0x1fe));
        assert_eq!(sign_mask_by_path("/vpn/conn"), Some(0x21e));
        assert_eq!(sign_mask_by_path("/vpn/report"), Some(0x21e));
        assert_eq!(sign_mask_by_path("/api/device/report"), Some(0x1fe));
        assert_eq!(sign_mask_by_path("/api/emgr/device/report"), Some(0x1fe));
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
    fn test_derive_sign_key_lowercases_company() {
        // info 用 company.to_lowercase()，故大小写不影响结果
        assert_eq!(
            derive_sign_key("ACME", "deadbeef"),
            derive_sign_key("acme", "deadbeef")
        );
    }

    #[test]
    fn test_build_canonical_1fe() {
        // 0x1fe 含全部 6 字段
        let c = build_canonical(
            0x1fe,
            "GET",
            "/api/vpn/list",
            "os=Android&os_version=2&timestamp=1700000000",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "csrf-token=abc; device_id=deadbeef",
            "abc",
        );
        assert_eq!(
            c,
            "GET\n/api/vpn/list\nos=Android&os_version=2&timestamp=1700000000\n\
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\
csrf-token=abc; device_id=deadbeef\nabc"
        );
    }

    #[test]
    fn test_build_canonical_21e_excludes_cookie_and_csrf() {
        // 0x21e 只含 method/urlPath/query/bodyHash
        let c = build_canonical(
            0x21e,
            "GET",
            "/api/vpn/list",
            "os=Android&os_version=2&timestamp=1700000000",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "csrf-token=abc; device_id=deadbeef",
            "abc",
        );
        assert_eq!(
            c,
            "GET\n/api/vpn/list\nos=Android&os_version=2&timestamp=1700000000\n\
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
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

    #[test]
    fn test_compute_sign_golden_1fe() {
        let sign = compute_sign(
            "acme",
            "deadbeef",
            "GET",
            "/api/vpn/list",
            "os=Android&os_version=2&timestamp=1700000000",
            b"",
            "csrf-token=abc; device_id=deadbeef",
            "abc",
            0x1fe,
        );
        assert_eq!(
            sign,
            "v1;CAEY/gMiIPHE6nULBu7lop8bVmm9vkrDf215cOpYudF90BIBvsDa"
        );
    }

    #[test]
    fn test_compute_sign_golden_21e() {
        let sign = compute_sign(
            "acme",
            "deadbeef",
            "POST",
            "/vpn/report",
            "os=Android&os_version=2&timestamp=1700000000",
            b"{}",
            "csrf-token=abc; device_id=deadbeef",
            "abc",
            0x21e,
        );
        assert_eq!(
            sign,
            "v1;CAEYngQiIOF6N9pQksfr7c2XwAd1fG+XXwGu9LEVpGuziNbLrG5c"
        );
    }
}
