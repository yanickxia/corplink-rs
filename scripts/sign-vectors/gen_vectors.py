#!/usr/bin/env python3
"""独立复算 CorpLink 请求签名，用于生成/校验 src/sign.rs 的黄金向量。
与 main.go 输出必须逐字节一致。"""
import hashlib, hmac, base64

IKM = b"TOK@@AoNfRIX+3bla%"

def hkdf_sha256(ikm, salt, info, length):
    if not salt:
        salt = b"\x00" * hashlib.sha256().digest_size
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 0
    while len(okm) < length:
        i += 1
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]

def derive_key(company, device_id):
    return hkdf_sha256(IKM, None, (company.lower() + "|" + device_id).encode(), 32)

def body_hash_hex(body): return hashlib.sha256(body).hexdigest()

def varint(n):
    out = bytearray()
    while n >= 0x80:
        out.append((n & 0x7f) | 0x80); n >>= 7
    out.append(n); return bytes(out)

def encode_payload(mask, digest):
    return b"\x08\x01\x18" + varint(mask) + b"\x22" + varint(len(digest)) + digest

CANON_BITS = [(1,"method"),(2,"urlPath"),(3,"query"),(4,"bodyHash"),(5,"cookieStr"),(7,"csrf")]

def build_canonical(mask, f):
    return "\n".join(f[name] for bit,name in CANON_BITS if (mask >> bit) & 1)

def compute_sign(company, device_id, method, path, query, body, cookie_str, csrf, mask):
    key = derive_key(company, device_id)
    f = {"method":method,"urlPath":path,"query":query,"bodyHash":body_hash_hex(body),
         "cookieStr":cookie_str,"csrf":csrf}
    digest = hmac.new(key, build_canonical(mask, f).encode(), hashlib.sha256).digest()
    return "v1;" + base64.b64encode(encode_payload(mask, digest)).decode()

if __name__ == "__main__":
    print("key_hex =", derive_key("acme","deadbeef").hex())
    print("golden_1fe =", compute_sign("acme","deadbeef","GET","/api/vpn/list",
          "os=Android&os_version=2&timestamp=1700000000", b"",
          "csrf-token=abc; device_id=deadbeef","abc",0x1fe))
    print("golden_21e =", compute_sign("acme","deadbeef","POST","/vpn/report",
          "os=Android&os_version=2&timestamp=1700000000", b"{}",
          "csrf-token=abc; device_id=deadbeef","abc",0x21e))
