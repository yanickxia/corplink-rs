// 用飞连 fork 同款 x/crypto/hkdf + crypto/hmac 复算签名，校验 gen_vectors.py / src/sign.rs。
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/hkdf"
)

var ikm = []byte("TOK@@AoNfRIX+3bla%")

func deriveKey(company, deviceID string) []byte {
	info := strings.ToLower(company) + "|" + deviceID
	r := hkdf.New(sha256.New, ikm, nil, []byte(info))
	key := make([]byte, 32)
	io.ReadAtLeast(r, key, 32)
	return key
}
func bodyHashHex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

var canonBits = []struct {
	bit  uint
	name string
}{{1, "method"}, {2, "urlPath"}, {3, "query"}, {4, "bodyHash"}, {5, "cookieStr"}, {7, "csrf"}}

func buildCanonical(mask uint64, f map[string]string) string {
	var parts []string
	for _, cb := range canonBits {
		if (mask>>cb.bit)&1 == 1 {
			parts = append(parts, f[cb.name])
		}
	}
	return strings.Join(parts, "\n")
}
func varint(n uint64) []byte {
	b := make([]byte, binary.MaxVarintLen64)
	return b[:binary.PutUvarint(b, n)]
}
func encodePayload(mask uint64, digest []byte) []byte {
	out := []byte{0x08, 0x01, 0x18}
	out = append(out, varint(mask)...)
	out = append(out, 0x22)
	out = append(out, varint(uint64(len(digest)))...)
	return append(out, digest...)
}
func computeSign(company, deviceID, method, path, query string, body []byte, cookieStr, csrf string, mask uint64) string {
	key := deriveKey(company, deviceID)
	f := map[string]string{"method": method, "urlPath": path, "query": query,
		"bodyHash": bodyHashHex(body), "cookieStr": cookieStr, "csrf": csrf}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(buildCanonical(mask, f)))
	return "v1;" + base64.StdEncoding.EncodeToString(encodePayload(mask, mac.Sum(nil)))
}
func main() {
	fmt.Println("key_hex =", hex.EncodeToString(deriveKey("acme", "deadbeef")))
	fmt.Println("golden_1fe =", computeSign("acme", "deadbeef", "GET", "/api/vpn/list",
		"os=Android&os_version=2&timestamp=1700000000", nil,
		"csrf-token=abc; device_id=deadbeef", "abc", 0x1fe))
	fmt.Println("golden_21e =", computeSign("acme", "deadbeef", "POST", "/vpn/report",
		"os=Android&os_version=2&timestamp=1700000000", []byte("{}"),
		"csrf-token=abc; device_id=deadbeef", "abc", 0x21e))
}
