#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
httpdump.py — Frida hook libssl.so 的 SSL_read/SSL_write,在进程外还原
              HTTP/1.1(明文)与 HTTP/2(HPACK)的完整请求/响应。

同时输出三份文件:
  <out>.log            完整明文流水(人类可读,含 headers + body)
  <out>.json           去重、过滤埋点后的结构化接口清单(api inventory)
  <out>.ndjson         每条请求一行 JSON 的全量原始记录(不去重,便于后处理)

用法:
    python3 httpdump.py 10057                          # 按 PID
    python3 httpdump.py com.volcengine.corplink:vpn    # :vpn 子进程
    python3 httpdump.py com.volcengine.corplink        # 主进程
    python3 httpdump.py 10057 capture_vpn              # 自定义输出前缀

先运行本脚本,再去 App 触发操作。Ctrl+C 结束并导出。
依赖: pip install frida hpack --user --break-system-packages
"""
import sys, os, json, signal, time, re, gzip
import frida
from hpack import Decoder

if len(sys.argv) < 2:
    print("用法: python3 httpdump.py <包名|PID> [输出前缀] [--attach]")
    print("  默认: 传包名 → spawn 拉起(从启动第一刻 hook,最全)")
    print("        传 PID  → attach 已运行进程")
    print("  --attach: 强制 attach 已运行的进程(不重启 App)")
    sys.exit(1)

argv = [a for a in sys.argv[1:] if a != "--attach"]
FORCE_ATTACH = "--attach" in sys.argv
target = argv[0]
prefix = argv[1] if len(argv) > 1 else "capture"
LOG_FILE   = prefix + ".log"
JSON_FILE  = prefix + ".json"
NDJSON_FILE= prefix + ".ndjson"

# 埋点 / 监控噪声过滤(命中即从结构化清单剔除,原始 ndjson 仍保留)
NOISE_HOST = ("mcs", "mon", "log", "apmplus", "umeng", "applog", "starling",
              "sentry", "crash", "slardar", "toutiao", "snssdk", "pangolin")
NOISE_PATH = ("/monitor", "/applog", "/log/", "/service/2/", "/list/tracer",
              "/v1/list", "/v1/report", "/settings/")

AGENT = r"""
function hook() {
  var m = Process.getModuleByName("libssl.so");
  var W = m.getExportByName("SSL_write");
  var R = m.getExportByName("SSL_read");
  Interceptor.attach(W, {
    onEnter: function (a) {
      var len = a[2].toInt32();
      if (len > 0) send({ssl: a[0].toString(), dir: "out"}, a[1].readByteArray(len));
    }
  });
  Interceptor.attach(R, {
    onEnter: function (a) { this.ssl = a[0]; this.buf = a[1]; },
    onLeave: function (r) {
      var len = r.toInt32();
      if (len > 0) send({ssl: this.ssl.toString(), dir: "in"}, this.buf.readByteArray(len));
    }
  });
  console.log("[*] libssl SSL_read/SSL_write hooked");
}
setImmediate(hook);
"""

PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
H1_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ",
              b"OPTIONS ", b"PATCH ", b"TRACE ", b"CONNECT ")

# ---- 全局状态 ----
CUR_SRC   = "?"  # 当前正在处理消息的来源进程名(Frida 消息串行分发)
proto     = {}   # ssl -> "h2" / "h1" / None(未定)
buffers   = {}   # (ssl,dir) -> bytearray
decoders  = {}   # (ssl,dir) -> hpack.Decoder
pending   = {}   # (ssl,dir) -> [sid, bytearray]  (h2 HEADERS/CONTINUATION 拼接)
streams   = {}   # (ssl,sid) -> dict            (h2 按流聚合)
h1state   = {}   # (ssl,dir) -> dict            (h1 报文解析状态机)
records   = []   # 结构化记录

logfp = open(LOG_FILE, "w", encoding="utf-8")
ndfp  = open(NDJSON_FILE, "w", encoding="utf-8")
rawfp = open(prefix + ".raw.log", "w", encoding="utf-8")

def out(line=""):
    print(line)
    logfp.write(line + "\n")
    logfp.flush()

def raw_tee(src, d, data):
    """原始层: 每一次 SSL_write/SSL_read 原样落盘,复刻老脚本,保证不漏。
    只写 <prefix>.raw.log,不打屏(避免刷屏),与结构化解析互不干扰。"""
    tag = "SSL_write (请求)" if d == "out" else "SSL_read (响应)"
    try:
        text = bytes(data).decode("utf-8")
        rawfp.write(f"\n========== [{src}] {tag} ({len(data)}) ==========\n")
        rawfp.write(text + "\n")
    except Exception:
        b = bytes(data)
        rawfp.write(f"\n========== [{src}] {tag} ({len(b)}, binary) ==========\n")
        # Response headers from the gateway can be larger than 512 bytes because
        # of tracing headers. Keep enough of binary/compressed reads to retain
        # trailing Set-Cookie headers while still bounding the diagnostic file.
        for i in range(0, min(len(b), 4096), 16):
            chunk = b[i:i+16]
            hexs = " ".join(f"{c:02x}" for c in chunk)
            asc = "".join(chr(c) if 32 <= c <= 126 else "." for c in chunk)
            rawfp.write(f"{i:08x}  {hexs:<47}  {asc}\n")
    rawfp.flush()

def is_noise(host, path):
    h, p = (host or "").lower(), (path or "").lower()
    if any(n in h for n in NOISE_HOST):
        return True
    if any(n in p for n in NOISE_PATH):
        return True
    return False

def body_json(raw):
    s = raw if isinstance(raw, str) else bytes(raw).decode("utf-8", "replace")
    try:
        return json.loads(s)
    except Exception:
        return s[:4000]

def decode_content(raw, headers):
    """Decode common HTTP content encodings before logging/JSON export."""
    data = bytes(raw)
    encoding = (headers or {}).get("content-encoding", "").lower()
    if encoding == "gzip" or data.startswith(b"\x1f\x8b"):
        try:
            return gzip.decompress(data)
        except Exception:
            pass
    return data

def header_map(headers):
    result = {}
    for k, v in headers:
        if k.startswith(":"):
            continue
        result[k] = f"{result[k]}\n{v}" if k in result else v
    return result

def record(method, host, path, status, req_headers, req_body,
           resp_headers, resp_body, ver):
    rec = {
        "time": time.strftime("%H:%M:%S"),
        "proc": CUR_SRC,
        "http": ver,
        "method": method,
        "host": host,
        "path": path,
        "status": status,
        "req_headers": req_headers,
        "resp_headers": resp_headers,
        "req_body": body_json(req_body),
        "resp_body": body_json(resp_body),
    }
    records.append(rec)
    ndfp.write(json.dumps(rec, ensure_ascii=False) + "\n")
    ndfp.flush()

# ============ HTTP/2 ============
def dec_for(key):
    return decoders.setdefault(key, Decoder())

def slot_for(ssl, sid):
    k = (ssl, sid)
    if k not in streams:
        streams[k] = {"req": None, "reqbody": bytearray(),
                      "resp": None, "respbody": bytearray(), "done": False}
    return streams[k]

def h(headers, name):
    for k, v in headers:
        if k == name:
            return v
    return ""

def h2_emit_headers(ssl, d, sid, block):
    try:
        headers = dec_for((ssl, d)).decode(bytes(block))
    except Exception as e:
        out(f"  <hpack decode error: {e}>")
        return
    s = slot_for(ssl, sid)
    if d == "out":
        s["req"] = headers
        out(f"\n──▶ REQ [h2] stream={sid} conn=..{ssl[-6:]}")
        out(f"     {h(headers,':method')} {h(headers,':path')}")
        if h(headers, ":authority"):
            out(f"     :authority: {h(headers,':authority')}")
        for k, v in headers:
            if not k.startswith(":"):
                out(f"     {k}: {v}")
    else:
        s["resp"] = headers
        out(f"\n◀── RESP [h2] stream={sid} conn=..{ssl[-6:]} status={h(headers,':status')}")
        for k, v in headers:
            if k == "set-cookie":
                out(f"     {k}: {v}")

def h2_body(ssl, d, sid, payload, end):
    s = slot_for(ssl, sid)
    (s["reqbody"] if d == "out" else s["respbody"]).extend(payload)
    if payload:
        txt = payload.decode("utf-8", "replace")
        out(f"     [{'req' if d=='out' else 'resp'} body stream={sid}] {txt[:800]}")
    if end and d == "in":
        h2_finalize(ssl, sid)

def h2_finalize(ssl, sid):
    s = streams.get((ssl, sid))
    if not s or s["done"] or not s["req"]:
        return
    s["done"] = True
    req, resp = s["req"], s["resp"] or []
    record(h(req, ":method"), h(req, ":authority"), h(req, ":path"),
           h(resp, ":status"),
           header_map(req), s["reqbody"], header_map(resp),
           s["respbody"], "2")

def h2_frame(ssl, d, ftype, flags, sid, payload):
    key = (ssl, d)
    if ftype == 0x1:                       # HEADERS
        data = payload
        if flags & 0x8:
            pad = data[0]; data = data[1:len(data)-pad]
        if flags & 0x20:
            data = data[5:]
        if flags & 0x4:
            h2_emit_headers(ssl, d, sid, data)
        else:
            pending[key] = [sid, bytearray(data)]
        if flags & 0x1:
            h2_body(ssl, d, sid, b"", True)
    elif ftype == 0x9:                     # CONTINUATION
        if key in pending:
            pending[key][1].extend(payload)
            if flags & 0x4:
                sid0, block = pending.pop(key)
                h2_emit_headers(ssl, d, sid0, block)
    elif ftype == 0x0:                     # DATA
        data = payload
        if flags & 0x8:
            pad = data[0]; data = data[1:len(data)-pad]
        h2_body(ssl, d, sid, data, bool(flags & 0x1))

def h2_feed(ssl, d, buf):
    while True:
        if d == "out" and buf[:len(PREFACE)] == PREFACE:
            del buf[:len(PREFACE)]
            continue
        if len(buf) < 9:
            break
        length = int.from_bytes(buf[0:3], "big")
        ftype, flags = buf[3], buf[4]
        sid = int.from_bytes(buf[5:9], "big") & 0x7fffffff
        if len(buf) < 9 + length:
            break
        payload = bytes(buf[9:9+length]); del buf[:9+length]
        try:
            h2_frame(ssl, d, ftype, flags, sid, payload)
        except Exception as e:
            out(f"  <h2 frame error: {e}>")

# ============ HTTP/1.1 ============
def h1_state(ssl, d):
    k = (ssl, d)
    if k not in h1state:
        h1state[k] = {"phase": "head", "head": bytearray(),
                      "clen": 0, "chunked": False, "body": bytearray(),
                      "start": ""}
    return h1state[k]

def h1_parse_head(raw):
    text = raw.decode("iso-8859-1")
    lines = text.split("\r\n")
    start = lines[0]
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            key, value = k.strip().lower(), v.strip()
            headers[key] = f"{headers[key]}\n{value}" if key in headers else value
    return start, headers

def h1_flush(ssl, d, st):
    """一条完整报文(head+body)就绪时输出。"""
    start = st["start"]
    body = bytes(st["body"])
    hdrs = st["hdrs"]
    if d == "out":
        # 请求行: METHOD PATH HTTP/1.1
        parts = start.split(" ")
        method = parts[0] if parts else ""
        path = parts[1] if len(parts) > 1 else ""
        host = hdrs.get("host", "")
        out(f"\n──▶ REQ [h1] conn=..{ssl[-6:]}")
        out(f"     {method} {path}")
        for k, v in hdrs.items():
            out(f"     {k}: {v}")
        if body:
            out(f"     [req body] {body.decode('utf-8','replace')[:800]}")
        st["_pend"] = {"method": method, "path": path, "host": host,
                       "hdrs": dict(hdrs), "body": body}
    else:
        parts = start.split(" ")
        status = parts[1] if len(parts) > 1 else ""
        out(f"\n◀── RESP [h1] conn=..{ssl[-6:]} status={status}")
        if "set-cookie" in hdrs:
            for value in hdrs["set-cookie"].split("\n"):
                out(f"     set-cookie: {value}")
        if body:
            out(f"     [resp body] {body.decode('utf-8','replace')[:800]}")
        # 用最近一次请求配对(H1 无并发时 keep-alive 严格顺序)
        req = h1state.get((ssl, "out"), {}).get("_pend_req")
        if req:
            record(req["method"], req["host"], req["path"], status,
                   req["hdrs"], req["body"], dict(hdrs), body, "1.1")
            h1state[(ssl, "out")]["_pend_req"] = None

def h1_feed(ssl, d, buf):
    st = h1_state(ssl, d)
    while buf:
        if st["phase"] == "head":
            idx = buf.find(b"\r\n\r\n")
            if idx < 0:
                break
            head = bytes(buf[:idx]); del buf[:idx+4]
            start, hdrs = h1_parse_head(head)
            st["start"], st["hdrs"] = start, hdrs
            te = hdrs.get("transfer-encoding", "")
            st["chunked"] = "chunked" in te.lower()
            st["clen"] = int(hdrs.get("content-length", "0") or 0)
            st["body"] = bytearray()
            st["phase"] = "chunk" if st["chunked"] else "body"
        elif st["phase"] == "body":
            need = st["clen"] - len(st["body"])
            if need <= 0:
                _h1_complete(ssl, d, st); continue
            take = min(need, len(buf))
            st["body"].extend(buf[:take]); del buf[:take]
            if len(st["body"]) >= st["clen"]:
                _h1_complete(ssl, d, st)
            else:
                break
        elif st["phase"] == "chunk":
            idx = buf.find(b"\r\n")
            if idx < 0:
                break
            size_line = bytes(buf[:idx])
            try:
                size = int(size_line.split(b";")[0], 16)
            except ValueError:
                del buf[:idx+2]; continue
            if size == 0:
                # 跳过尾部 \r\n(可能还有 trailer,简化处理)
                end = buf.find(b"\r\n\r\n")
                if end >= 0:
                    del buf[:end+4]
                else:
                    del buf[:idx+2]
                _h1_complete(ssl, d, st); continue
            if len(buf) < idx + 2 + size + 2:
                break
            chunk = bytes(buf[idx+2: idx+2+size])
            st["body"].extend(chunk)
            del buf[:idx+2+size+2]

def _h1_complete(ssl, d, st):
    # 请求侧:暂存待与响应配对
    if d == "out":
        st["_pend_req"] = {"method": st["start"].split(" ")[0],
                           "path": (st["start"].split(" ")+["",""])[1],
                           "host": st["hdrs"].get("host", ""),
                           "hdrs": dict(st["hdrs"]),
                           "body": bytes(st["body"])}
        parts = st["start"].split(" ")
        out(f"\n──▶ REQ [h1] conn=..{ssl[-6:]}")
        out(f"     {parts[0]} {(parts+['',''])[1]}")
        for k, v in st["hdrs"].items():
            out(f"     {k}: {v}")
        if st["body"]:
            out(f"     [req body] {bytes(st['body']).decode('utf-8','replace')[:800]}")
    else:
        parts = st["start"].split(" ")
        status = (parts + ["", ""])[1]
        body = decode_content(st["body"], st["hdrs"])
        out(f"\n◀── RESP [h1] conn=..{ssl[-6:]} status={status}")
        if "set-cookie" in st["hdrs"]:
            for value in st["hdrs"]["set-cookie"].split("\n"):
                out(f"     set-cookie: {value}")
        if body:
            out(f"     [resp body] {body.decode('utf-8','replace')[:800]}")
        req = h1state.get((ssl, "out"), {}).get("_pend_req")
        if req:
            record(req["method"], req["host"], req["path"], status,
                   req["hdrs"], req["body"], dict(st["hdrs"]), body, "1.1")
            h1state[(ssl, "out")]["_pend_req"] = None
    st["phase"] = "head"; st["body"] = bytearray()

# ============ 协议分派 ============
def looks_like_h2_frame(buf):
    """严格校验 buf 是否以一个合法 HTTP/2 帧开头。
    返回 True=像h2 / False=肯定不是 / None=数据不足待定。"""
    if len(buf) < 9:
        return None
    length = int.from_bytes(buf[0:3], "big")
    ftype = buf[3]
    # 帧类型 0..9,长度不至于离谱(HTTP/1.1 文本首字节当长度算会极大)
    if ftype <= 0x9 and length <= (1 << 20):
        return True
    return False

def h1_start_index(buf, d):
    """在(可能夹着 mid-stream 垃圾的)buf 中找 HTTP/1.1 报文起点。-1=没找到。"""
    if d == "out":
        best = -1
        for m in H1_METHODS:
            i = buf.find(m)
            while i != -1:
                if i == 0 or buf[i - 1] == 0x0a:   # 行首(紧跟 \n 或在开头)
                    if best == -1 or i < best:
                        best = i
                    break
                i = buf.find(m, i + 1)
        return best
    else:
        i = buf.find(b"HTTP/1.")
        while i != -1:
            if i == 0 or buf[i - 1] == 0x0a:
                return i
            i = buf.find(b"HTTP/1.", i + 1)
        return -1

def detect_and_align(ssl, d, buf):
    """判定协议;必要时丢弃 mid-stream 垃圾前缀让 h1 对齐。
    返回 "h2" / "h1" / None(继续等更多数据)。"""
    # 1) 干净的 h2 preface
    if buf[:len(PREFACE)] == PREFACE:
        return "h2"
    # 2) h1 明确特征(优先,且能跳过 mid-stream 垃圾前缀)
    idx = h1_start_index(buf, d)
    if idx != -1:
        if idx > 0:
            del buf[:idx]           # 丢弃 mid-stream 垃圾,对齐到请求行/状态行
        return "h1"
    # 3) 严格校验是否像 h2 帧
    lk = looks_like_h2_frame(buf)
    if lk is True:
        return "h2"
    if lk is False:
        # 既不是 h1 也不是合法 h2 —— 可能是自定义/二进制协议。
        # 攒够一定数据后转 raw 兜底(原始 hexdump),避免默默丢弃。
        if len(buf) >= 32:
            return "raw"
        return None
    return None                     # 数据不足,等更多

def hexdump(b):
    lines = []
    for i in range(0, len(b), 16):
        chunk = b[i:i+16]
        hexs = " ".join(f"{c:02x}" for c in chunk)
        ascii_ = "".join(chr(c) if 32 <= c <= 126 else "." for c in chunk)
        lines.append(f"     {i:08x}  {hexs:<47}  {ascii_}")
    return "\n".join(lines)

# 在 raw 流里捞 HTTP/1 请求行(中途接入的长连接靠这个救回)
H1_REQ_RE = re.compile(
    rb'(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT) [^\r\n]{1,3000} HTTP/1\.[01]\r\n')

def raw_feed(ssl, d, buf):
    """兜底: 原始 hexdump / 文本转储,并尝试从中捞出 h1 请求行。"""
    data = bytes(buf); del buf[:]
    if not data:
        return
    tag = "OUT" if d == "out" else "IN "
    for m in H1_REQ_RE.finditer(data):
        line = m.group().rstrip(b"\r\n").decode("iso-8859-1")
        out(f"\n──▶ [raw-h1] conn=..{ssl[-6:]}  {line}")
    printable = sum(1 for c in data if 9 <= c <= 13 or 32 <= c <= 126)
    if printable / max(len(data), 1) > 0.75:
        txt = data.decode("utf-8", "replace")
        out(f"\n[{tag} raw text] conn=..{ssl[-6:]} ({len(data)}B)")
        out("     " + txt[:1200].replace("\n", "\n     "))
    else:
        out(f"\n[{tag} raw bin] conn=..{ssl[-6:]} ({len(data)}B)")
        out(hexdump(data[:512]))

def feed(ssl, d, data):
    buf = buffers.setdefault((ssl, d), bytearray())
    buf.extend(data)
    p = proto.get(ssl)
    if p is None:
        p = detect_and_align(ssl, d, buf)
        if p:
            proto[ssl] = p
            if p != "h2":
                out(f"[i] conn=..{ssl[-6:]} 判定为 {p.upper()}")
        else:
            return
    if p == "h2":
        h2_feed(ssl, d, buf)
    elif p == "h1":
        h1_feed(ssl, d, buf)
    else:
        raw_feed(ssl, d, buf)

def make_on_message(src):
    """为每个进程生成带来源标注的消息回调。"""
    def _cb(msg, data):
        global CUR_SRC
        if msg["type"] == "send" and data is not None:
            pl = msg["payload"]
            CUR_SRC = src
            # ① 原始层: 先原样落盘,保证一个字节都不漏(复刻老脚本)
            raw_tee(src, pl["dir"], data)
            # ② 结构化层: 再喂协议解析器
            # 指针加进程前缀,避免不同进程 SSL* 地址相同造成串流
            feed(f"{src}#{pl['ssl']}", pl["dir"], data)
        elif msg["type"] == "error":
            out(f"[frida error][{src}] " + str(msg.get("stack") or msg))
    return _cb

def dump_and_exit(*_):
    dedup = {}
    for r in records:
        dedup[(r["method"], r["path"].split("?")[0])] = r
    inv = [r for r in dedup.values() if not is_noise(r["host"], r["path"])]
    inv.sort(key=lambda r: (r["proc"], r["host"], r["path"]))
    with open(JSON_FILE, "w", encoding="utf-8") as f:
        json.dump(inv, f, ensure_ascii=False, indent=2)
    out(f"\n\n[*] 原始 {len(records)} 条 → {NDJSON_FILE}")
    out(f"[*] 去重过滤后 {len(inv)} 个接口 → {JSON_FILE}")
    out(f"[*] 完整流水 → {LOG_FILE}")
    out(f"[*] 原始明文(不漏,复刻老脚本)→ {prefix}.raw.log")
    out("[*] 接口清单:")
    for r in inv:
        out(f"    [{r['proc']}] [h{r['http']}] {r['method']:6} {r['host']}{r['path']}  [{r['status']}]")
    logfp.close(); ndfp.close(); rawfp.close()
    sys.exit(0)

# 已附加的进程: pid -> session
_sessions = {}

def attach_one(dev, proc):
    """给单个进程注入 agent。proc 为 frida Process 对象。"""
    if proc.pid in _sessions:
        return
    try:
        session = dev.attach(proc.pid)
        script = session.create_script(AGENT)
        script.on("message", make_on_message(proc.name))
        script.load()
        _sessions[proc.pid] = session
        out(f"[+] attached  pid={proc.pid}  {proc.name}")
    except Exception as e:
        out(f"[!] attach 失败 pid={proc.pid} {proc.name}: {e}")

def match_procs(dev, target):
    """按包名匹配:主进程 + 所有 :xxx 子进程。"""
    res = []
    for p in dev.enumerate_processes():
        if p.name == target or p.name.startswith(target + ":"):
            res.append(p)
    return res

def poller(target, stop):
    """后台轮询,把新孵化的子进程(如点连接后才起的 :vpn)自动补挂。"""
    while not stop.is_set():
        try:
            # 在子线程里重新获取 device,避免 Frida device 对象线程安全问题
            dev = frida.get_usb_device()
            for p in match_procs(dev, target):
                if p.pid not in _sessions:
                    attach_one(dev, p)
        except Exception:
            pass
        stop.wait(0.3)

def spawn_main(dev, pkg):
    """spawn 拉起主进程:在 resume 前注入 hook,抓到 App 启动阶段的早期连接。"""
    out(f"[*] spawn 拉起 {pkg} ...")
    pid = dev.spawn([pkg])
    session = dev.attach(pid)
    script = session.create_script(AGENT)
    script.on("message", make_on_message(pkg))
    script.load()
    _sessions[pid] = session
    out(f"[+] spawned & hooked  pid={pid}  {pkg}(启动前已注入)")
    dev.resume(pid)
    out(f"[*] resumed pid={pid} — App 开始运行")

def main():
    dev = frida.get_usb_device()
    signal.signal(signal.SIGINT, dump_and_exit)
    out(f"[*] target={target}  output={prefix}.(log|json|ndjson|raw.log)")

    if target.isdigit():
        # 纯数字 → attach 单 PID
        try:
            session = dev.attach(int(target))
            script = session.create_script(AGENT)
            script.on("message", make_on_message(f"pid{target}"))
            script.load()
            _sessions[int(target)] = session
            out(f"[+] attached  pid={target}")
        except Exception as e:
            out(f"[!] attach 失败: {e}"); sys.exit(1)
    elif FORCE_ATTACH:
        # 包名 + --attach → attach 所有已运行的匹配进程
        procs = match_procs(dev, target)
        if not procs:
            out(f"[!] 没找到匹配 '{target}' 的进程,请确认 App 已启动。")
            sys.exit(1)
        for p in procs:
            attach_one(dev, p)
    else:
        # 包名(默认)→ spawn 拉起主进程,从启动第一刻 hook(最全)
        try:
            spawn_main(dev, target)
        except Exception as e:
            out(f"[!] spawn 失败: {e}")
            out("    退回 attach 已运行进程 ...")
            procs = match_procs(dev, target)
            if not procs:
                out(f"[!] 也没找到已运行的 '{target}' 进程,退出。"); sys.exit(1)
            for p in procs:
                attach_one(dev, p)

    # 无论 spawn 还是 attach,都开轮询:补挂所有子进程(:channel/:vpn 等)
    if not target.isdigit():
        import threading
        stop = threading.Event()
        t = threading.Thread(target=poller, args=(target, stop), daemon=True)
        t.start()

    out("[*] running — 现在去 App 完整走一遍(登录、拉节点、点连接)。Ctrl+C 结束并导出。")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
