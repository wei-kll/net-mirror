#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_sub.py v2 - 多源抓取 + 多档安全 sing-box 订阅

背景：原单源 Au1rxx/free-vpn-subscriptions 自 2026-10-30 起停止更新（数据冻结 18 天），
所有节点早已失效 -> 订阅"用不了/更新也没换到新节点"。

v2 改为多源合并：
  1. mahdibland/V2RayAggregator  Eternity.txt     已过连通测试的优选节点
  2. mahdibland/V2RayAggregator  EternityAir.txt  轻量优选
  3. mahdibland/V2RayAggregator  sub/sub_merge.txt 全量池
  4. 0xRadikal/Free-v2ray-Configs verified/singbox.json 已验证 sing-box 池（含 VLESS-Reality）
  5. 0xRadikal/Free-v2ray-Configs all/singbox.json 全量 sing-box 池（10k+）
  6. radarhub.top/sing-box.json 可选（国内常被 reset，失败不影响）

流程：解析 URI -> 安全过滤 -> 国家标注 -> 排名 -> 按出口 host 去重 -> TCP 可达性探测 -> 分档输出
输出文件名不变（Hiddify 里配置名 = URL 末段）：
  sub（全量优选，默认档）/ sub-asia（日韩新港台+东南亚）/ sub-us（美加）/ sub-eu（欧洲备胎）

安全规则
 1. 非 SS 节点必须 TLS 且强制校验证书（tls.insecure / allowInsecure=1 一律剔除）
 2. 剔除明文（security=none）、弱加密 SS（非 AEAD）、裸 http/socks/ssr
 3. 同一出口 host 只留 1 个节点（先排序，留质量最高的那条）
 4. selector 首项固定节点，AUTO(urltest) 放最后，不自动跳出口
 5. CN 落地/中转节点不进订阅

可调环境变量：MAX_NODES / MAX_ASIA / MAX_US / MAX_EU / ONLY_CC / BAN_CC /
              PROBE(0/1) / PROBE_LIMIT / PROBE_TIMEOUT / PROBE_THREADS / PROBE_BUDGET
"""
import base64
import copy
import json
import os
import re
import socket
import sys
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

SOURCES = [
    ("tested", "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity.txt"),
    ("tested", "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/EternityAir.txt"),
    ("pool", "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt"),
]
SINGBOX_SOURCES = [
    ("tested", "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/singbox.json"),
    ("pool", "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/singbox.json"),
    ("tested", "https://radarhub.top/sing-box.json"),
]

AEAD_SS = ("aes-256-gcm", "aes-128-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
           "aes-192-gcm")
NEAR = {"JP": 7, "KR": 6, "SG": 6, "HK": 6, "TW": 6, "MO": 5, "MY": 5, "TH": 5, "VN": 5,
        "US": 3, "CA": 2, "AU": 3, "PH": 4, "ID": 4, "IN": 3}
ASIA = {"JP", "KR", "SG", "HK", "TW", "MO", "MY", "TH", "VN", "PH", "ID", "AU", "NZ", "IN",
        "KH", "LA", "BD", "PK"}
AMER = {"US", "CA", "MX", "BR"}
EURO = {"GB", "DE", "NL", "FR", "IT", "ES", "SE", "NO", "FI", "DK", "PL", "EE", "LT", "LV",
        "AT", "CH", "IE", "CZ", "BE", "PT", "GR", "RO", "UA", "HU", "SK", "HR", "BG", "IS",
        "RU", "MD", "RS", "SI", "LU", "MT", "CY", "AL", "BA", "MK", "ME", "TR"}

NAME2CC = {
    "japan": "JP", "korea": "KR", "south korea": "KR", "singapore": "SG", "hong kong": "HK",
    "hongkong": "HK", "hk": "HK", "taiwan": "TW", "macau": "MO", "macao": "MO",
    "malaysia": "MY", "thailand": "TH", "vietnam": "VN", "viet nam": "VN", "philippines": "PH",
    "indonesia": "ID", "india": "IN", "australia": "AU", "new zealand": "NZ",
    "united states": "US", "usa": "US", "america": "US", "united kingdom": "GB", "uk": "GB",
    "britain": "GB", "germany": "DE", "netherlands": "NL", "holland": "NL", "france": "FR",
    "italy": "IT", "spain": "ES", "sweden": "SE", "norway": "NO", "finland": "FI",
    "denmark": "DK", "poland": "PL", "estonia": "EE", "lithuania": "LT", "latvia": "LV",
    "austria": "AT", "switzerland": "CH", "ireland": "IE", "czech": "CZ", "belgium": "BE",
    "portugal": "PT", "greece": "GR", "romania": "RO", "ukraine": "UA", "hungary": "HU",
    "slovakia": "SK", "croatia": "HR", "bulgaria": "BG", "iceland": "IS", "russia": "RU",
    "moldova": "MD", "serbia": "RS", "slovenia": "SI", "luxembourg": "LU", "malta": "MT",
    "cyprus": "CY", "turkey": "TR", "canada": "CA", "mexico": "MX", "brazil": "BR",
    "cambodia": "KH", "laos": "LA", "bangladesh": "BD", "pakistan": "PK",
}

MAX_NODES = int(os.environ.get("MAX_NODES", "250"))
VARIANTS = [
    ("sub", None, MAX_NODES, 25),
    ("sub-asia", ASIA, int(os.environ.get("MAX_ASIA", "140")), 8),
    ("sub-us", AMER, int(os.environ.get("MAX_US", "140")), 8),
    ("sub-eu", EURO, int(os.environ.get("MAX_EU", "140")), 8),
]
ONLY_CC = {c.strip().upper() for c in os.environ.get("ONLY_CC", "").split(",") if c.strip()}
PROBE = os.environ.get("PROBE", "1") != "0"
PROBE_LIMIT = int(os.environ.get("PROBE_LIMIT", "2000"))
PROBE_TIMEOUT = float(os.environ.get("PROBE_TIMEOUT", "2.0"))
PROBE_THREADS = int(os.environ.get("PROBE_THREADS", "200"))
PROBE_BUDGET = float(os.environ.get("PROBE_BUDGET", "240"))
BAN_CC = {"CN"} | {c.strip().upper() for c in os.environ.get("BAN_CC", "").split(",") if c.strip()}


def http_get(url, timeout=60, retries=3):
    last = None
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(1 + 2 * i)
    raise RuntimeError("%s (%s)" % (url, last))


def load_uri_source(url):
    raw = http_get(url).decode("utf-8", "replace").strip()
    if raw.startswith("{"):
        return []
    if "://" not in raw:
        try:
            raw = base64.b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            return []
    return [ln.strip() for ln in raw.splitlines() if "://" in ln]


def b64d(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return ""


def qs(q):
    return {k: v[0] for k, v in urllib.parse.parse_qs(q, keep_blank_values=True).items()}


def truthy(v):
    return str(v).lower() in ("1", "true", "yes")


def host_of(server):
    return str(server).lower().strip("[]")


def split_hostport(s):
    s = s.split("/", 1)[0]
    if s.startswith("["):
        host, _, port = s.partition("]")
        return host.strip("[]"), int((port or ":0").lstrip(":"))
    host, _, port = s.rpartition(":")
    try:
        return host, int(port)
    except ValueError:
        return host, 0


def parse_ss(uri):
    body = uri[5:].split("#", 1)[0]
    name = urllib.parse.unquote(uri.split("#", 1)[1]) if "#" in uri else ""
    plugin = ""
    if "?" in body:
        body, q = body.split("?", 1)
        plugin = qs(q).get("plugin", "")
    if plugin:
        return None
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        dec = b64d(userinfo)
        if ":" not in dec:
            return None
        method, password = dec.split(":", 1)
        host, port = split_hostport(hostport)
    else:
        dec = b64d(body)
        if "@" not in dec:
            return None
        userinfo, hostport = dec.rsplit("@", 1)
        if ":" not in userinfo:
            return None
        method, password = userinfo.split(":", 1)
        host, port = split_hostport(hostport)
    if not method.lower().startswith(AEAD_SS):
        return ("drop", "weak_cipher")
    return {"type": "shadowsocks", "tag": name, "server": host, "server_port": port,
            "method": method.lower(), "password": password}


def transport_from(params, default_path="/"):
    t = (params.get("type") or "tcp").lower()
    if t in ("ws", "websocket"):
        h = {}
        if params.get("host"):
            h["Host"] = params["host"]
        return {"type": "ws", "path": params.get("path") or default_path, "headers": h}
    if t == "grpc":
        return {"type": "grpc", "service_name": params.get("serviceName") or params.get("path") or ""}
    if t in ("http", "h2", "h2c"):
        h = {}
        if params.get("host"):
            h["Host"] = params["host"]
        return {"type": "http", "path": params.get("path") or default_path,
                "host": [params["host"]] if params.get("host") else []}
    return None


def tls_block(params):
    sni = params.get("sni") or params.get("peer")
    insecure = truthy(params.get("insecure", "")) or truthy(params.get("allowInsecure", ""))
    sec = (params.get("security") or "").lower()
    if sec == "none":
        return ("drop", "plaintext")
    if insecure:
        return ("drop", "insecure_cert")
    blk = {"enabled": True}
    if sni:
        blk["server_name"] = sni
    if params.get("alpn"):
        blk["alpn"] = [a for a in urllib.parse.unquote(params["alpn"]).split(",") if a]
    fp = params.get("fp") or params.get("fingerprint")
    if fp:
        blk["utls"] = {"enabled": True, "fingerprint": fp}
    pbk = params.get("pbk") or params.get("publicKey")
    if pbk:
        blk["reality"] = {"enabled": True, "public_key": urllib.parse.unquote(pbk),
                          "short_id": params.get("sid", "")}
    return blk


def parse_vless(uri):
    u = urllib.parse.urlsplit(uri)
    if not u.username or not u.hostname:
        return None
    params = qs(u.query)
    name = urllib.parse.unquote(u.fragment)
    tl = tls_block(params)
    if isinstance(tl, tuple):
        return tl
    node = {"type": "vless", "tag": name, "server": u.hostname, "server_port": u.port or 443,
            "uuid": urllib.parse.unquote(u.username), "tls": tl}
    if params.get("flow"):
        node["flow"] = params["flow"]
    tr = transport_from(params)
    if tr:
        node["transport"] = tr
    return node


def parse_trojan(uri):
    u = urllib.parse.urlsplit(uri)
    if not u.username or not u.hostname:
        return None
    params = qs(u.query)
    name = urllib.parse.unquote(u.fragment)
    tl = tls_block(params)
    if isinstance(tl, tuple):
        return tl
    node = {"type": "trojan", "tag": name, "server": u.hostname, "server_port": u.port or 443,
            "password": urllib.parse.unquote(u.username), "tls": tl}
    tr = transport_from(params)
    if tr:
        node["transport"] = tr
    return node


def parse_vmess(uri):
    dec = b64d(uri[8:])
    if not dec:
        return None
    try:
        j = json.loads(dec)
    except Exception:  # noqa: BLE001
        return None
    add, port, uid = j.get("add"), j.get("port"), j.get("id")
    if not (add and port and uid):
        return None
    name = j.get("ps") or ""
    if str(j.get("tls", "")).lower() != "tls":
        return ("drop", "plaintext")
    if truthy(j.get("insecure", "")) or truthy(j.get("allowInsecure", "")):
        return ("drop", "insecure_cert")
    tl = {"enabled": True}
    sni = j.get("sni") or j.get("host")
    if sni:
        tl["server_name"] = sni
    if j.get("alpn"):
        tl["alpn"] = [a for a in str(j["alpn"]).split(",") if a]
    if j.get("fp"):
        tl["utls"] = {"enabled": True, "fingerprint": j["fp"]}
    node = {"type": "vmess", "tag": name, "server": add, "server_port": int(port),
            "uuid": uid, "security": (j.get("scy") or "auto") or "auto",
            "alter_id": int(j.get("aid") or 0), "tls": tl}
    net = (j.get("net") or "tcp").lower()
    if net == "ws":
        h = {}
        if j.get("host"):
            h["Host"] = j["host"]
        node["transport"] = {"type": "ws", "path": j.get("path") or "/", "headers": h}
    elif net == "grpc":
        node["transport"] = {"type": "grpc", "service_name": j.get("path") or ""}
    return node


def parse_hysteria2(uri):
    u = urllib.parse.urlsplit(uri)
    if not u.hostname:
        return None
    params = qs(u.query)
    name = urllib.parse.unquote(u.fragment)
    tl = {"enabled": True, "alpn": ["h3"]}
    if params.get("sni"):
        tl["server_name"] = params["sni"]
    if truthy(params.get("insecure", "")):
        return ("drop", "insecure_cert")
    if params.get("alpn"):
        tl["alpn"] = [a for a in urllib.parse.unquote(params["alpn"]).split(",") if a]
    node = {"type": "hysteria2", "tag": name, "server": u.hostname,
            "server_port": u.port or 443, "password": urllib.parse.unquote(u.username or ""),
            "tls": tl}
    if params.get("obfs") or params.get("obfs-password"):
        ob = {"type": params.get("obfs") or "salamander"}
        if params.get("obfs-password"):
            ob["password"] = params["obfs-password"]
        node["obfs"] = ob
    return node


def parse_tuic(uri):
    u = urllib.parse.urlsplit(uri)
    if not u.hostname or not u.username:
        return None
    params = qs(u.query)
    name = urllib.parse.unquote(u.fragment)
    if truthy(params.get("insecure", "")) or truthy(params.get("allow_insecure", "")):
        return ("drop", "insecure_cert")
    tl = {"enabled": True}
    if params.get("sni"):
        tl["server_name"] = params["sni"]
    if params.get("alpn"):
        tl["alpn"] = [a for a in urllib.parse.unquote(params["alpn"]).split(",") if a]
    node = {"type": "tuic", "tag": name, "server": u.hostname, "server_port": u.port or 443,
            "uuid": urllib.parse.unquote(u.username),
            "password": urllib.parse.unquote(u.password or ""), "tls": tl}
    if params.get("congestion_control"):
        node["congestion_control"] = params["congestion_control"]
    return node


PARSERS = {"ss": parse_ss, "vless": parse_vless, "trojan": parse_trojan, "vmess": parse_vmess,
           "hysteria2": parse_hysteria2, "hy2": parse_hysteria2, "tuic": parse_tuic}


def parse_uri(uri):
    scheme = uri.split("://", 1)[0].lower()
    fn = PARSERS.get(scheme)
    if not fn:
        return ("drop", "scheme_" + scheme)
    try:
        return fn(uri)
    except Exception:  # noqa: BLE001
        return ("drop", "parse_error")


def cc_from_text(text):
    if not text:
        return None
    for i, ch in enumerate(text):
        if "\U0001F1E6" <= ch <= "\U0001F1FF":
            if i + 1 < len(text) and "\U0001F1E6" <= text[i + 1] <= "\U0001F1FF":
                a = chr(ord(ch) - 0x1F1E6 + ord("A"))
                b = chr(ord(text[i + 1]) - 0x1F1E6 + ord("A"))
                return a + b
    low = text.lower()
    for nm, cc in sorted(NAME2CC.items(), key=lambda x: -len(x[0])):
        if nm in low:
            return cc
    for tok in re.split(r"[^A-Za-z]+", text):
        if len(tok) == 2 and tok.isupper():
            return tok
    return None


IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def resolve_hosts(hosts, threads=200):
    cache, todo = {}, []
    for h in set(hosts):
        if IPV4_RE.match(h):
            cache[h] = h
        else:
            todo.append(h)

    def one(h):
        try:
            infos = socket.getaddrinfo(h, None, socket.AF_INET, socket.SOCK_STREAM)
            return h, (infos[0][4][0] if infos else None)
        except Exception:  # noqa: BLE001
            return h, None

    if todo:
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for h, ip in ex.map(one, todo):
                cache[h] = ip
    return cache


def probe_one(node, ipmap, deadline):
    host = host_of(node["server"])
    port = int(node.get("server_port") or 0)
    if not port:
        return False
    ip = ipmap.get(host)
    if not ip or time.time() > deadline:
        return False
    left = max(0.4, min(PROBE_TIMEOUT, deadline - time.time()))
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(left)
        try:
            s.connect((ip, port))
            return True
        finally:
            s.close()
    except Exception:  # noqa: BLE001
        return False


def probe(nodes):
    if not PROBE or not nodes:
        return nodes, 0, 0
    cand = nodes[:PROBE_LIMIT]
    ipmap = resolve_hosts([n["server"] for n in cand])
    deadline = time.time() + PROBE_BUDGET
    with ThreadPoolExecutor(max_workers=PROBE_THREADS) as ex:
        ok = list(ex.map(lambda n: probe_one(n, ipmap, deadline), cand))
    alive = [n for n, k in zip(cand, ok) if k]
    return alive, sum(1 for k in ok if not k), len(nodes) - len(cand)


def render(nodes, ccs):
    out, seq = [], {}
    for o, cc in zip(nodes, ccs):
        o = copy.deepcopy(o)
        o.pop("comments", None)
        o.pop("_tested", None)
        t = o["type"]
        seq[t] = seq.get(t, 0) + 1
        o["tag"] = "%s %s-%02d" % (cc, t, seq[t])
        out.append(o)
    if not out:
        return None, []
    tags = [o["tag"] for o in out]
    cfg = {
        "outbounds": [
            {"tag": "select", "type": "selector", "outbounds": tags + ["AUTO"]},
            {"tag": "AUTO", "type": "urltest", "outbounds": tags,
             "url": "https://www.gstatic.com/generate_204", "interval": "15m", "tolerance": 120},
            {"tag": "direct", "type": "direct"},
        ] + out,
        "route": {"final": "select"},
    }
    return cfg, out


def fair_pick(labeled, limit):
    buckets = {}
    for item in labeled:
        buckets.setdefault(item[2], []).append(item)
    quota = max(8, limit // max(1, len(buckets)))
    picked, picked_ids = [], set()

    def add(item):
        if id(item[1]) in picked_ids or len(picked) >= limit:
            return
        picked_ids.add(id(item[1]))
        picked.append(item)

    for cc, lst in buckets.items():
        for item in lst[:quota]:
            add(item)
    for item in labeled:
        add(item)
    return picked


def main():
    dropped = {}

    def drop(why, n=1):
        dropped[why] = dropped.get(why, 0) + n

    raw, per_source = [], {}
    for kind, url in SOURCES:
        try:
            lines = load_uri_source(url)
            per_source[url.rsplit("/", 1)[-1]] = len(lines)
            raw.extend((kind, ln) for ln in lines)
        except Exception as e:  # noqa: BLE001
            sys.stderr.write("source failed: %s (%s)\n" % (url, e))
            per_source[url.rsplit("/", 1)[-1]] = "fail"
    for kind, url in SINGBOX_SOURCES:
        key = urllib.parse.urlsplit(url).netloc
        try:
            data = json.loads(http_get(url, timeout=90).decode("utf-8", "replace"))
            got = 0
            for o in data.get("outbounds", []):
                if o.get("server") and o.get("type") in ("vless", "vmess", "trojan",
                                                         "hysteria2", "tuic", "shadowsocks"):
                    raw.append((kind, o))
                    got += 1
            per_source[key] = got
        except Exception as e:  # noqa: BLE001
            per_source[key] = "fail(%s)" % type(e).__name__

    nodes = []
    for kind, item in raw:
        if isinstance(item, dict):
            nodes.append((kind, item))
            continue
        r = parse_uri(item)
        if r is None:
            drop("unparsed")
        elif isinstance(r, tuple):
            drop(r[1])
        else:
            nodes.append((kind, r))

    safe = []
    for kind, o in nodes:
        t = o.get("type")
        tls = o.get("tls") or {}
        if t != "shadowsocks":
            if not tls.get("enabled"):
                drop("plaintext")
                continue
            if tls.get("insecure"):
                drop("insecure_cert")
                continue
        else:
            if not str(o.get("method", "")).lower().startswith(AEAD_SS):
                drop("weak_cipher")
                continue
        if not o.get("server") or not o.get("server_port"):
            drop("no_server")
            continue
        safe.append((kind, o))

    labeled, unknown = [], 0
    for kind, o in safe:
        cc = cc_from_text(o.get("tag", ""))
        if not cc:
            unknown += 1
            cc = "??"
        labeled.append((kind, o, cc))

    def rank(item):
        kind, o, cc = item
        if (o.get("tls") or {}).get("reality"):
            p = 4
        elif o.get("type") in ("trojan", "vless", "hysteria2", "tuic"):
            p = 2
        else:
            p = 1
        return (100 if kind == "tested" else 0) + NEAR.get(cc, 0) * 10 + p

    labeled.sort(key=rank, reverse=True)
    seen, uniq = set(), []
    for item in labeled:
        h = host_of(item[1]["server"])
        if h in seen:
            drop("dup_exit")
            continue
        if item[2] in BAN_CC:
            drop("banned_cc")
            continue
        seen.add(h)
        uniq.append(item)
    labeled = uniq

    if ONLY_CC:
        labeled = [x for x in labeled if x[2] in ONLY_CC]

    alive_nodes, dead, unprobed = probe([o for _, o, _ in fair_pick(labeled, PROBE_LIMIT)])
    alive_keys = {id(o) for o in alive_nodes}
    if PROBE:
        labeled = sorted([x for x in labeled if id(x[1]) in alive_keys], key=rank, reverse=True)
        drop("tcp_dead", dead)
        if unprobed:
            drop("not_probed", unprobed)

    stats = {
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sources": per_source,
        "raw_uris": len(raw),
        "parsed": len(nodes),
        "safe": len(safe),
        "unique_exits": len(uniq),
        "alive_exits": len(labeled),
        "unlabeled_country": unknown,
        "probe": {"enabled": PROBE, "limit": PROBE_LIMIT, "timeout_s": PROBE_TIMEOUT},
        "dropped": dropped,
        "tiers": {},
        "note": "每档 selector 默认固定节点；AUTO 会换出口，Google 登录等敏感操作勿用 AUTO",
    }

    main_failed = False
    for name, ccset, cap, minimum in VARIANTS:
        sel = [x for x in labeled if ccset is None or x[2] in ccset][:cap]
        if len(sel) < minimum:
            sys.stderr.write("tier %s only %d (<%d), skip\n" % (name, len(sel), minimum))
            stats["tiers"][name] = {"skipped": True, "usable": len(sel)}
            if name == "sub":
                main_failed = True
            continue
        cfg, out = render([o for _, o, _ in sel], [c for _, _, c in sel])
        with open(name, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=1)
        pr, ct = {}, {}
        for (_, o, c) in sel:
            pr[o["type"]] = pr.get(o["type"], 0) + 1
            ct[c] = ct.get(c, 0) + 1
        stats["tiers"][name] = {"nodes": len(out), "default": out[0]["tag"],
                                "protocols": pr, "countries": ct}

    with open("sub-stats.json", "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    if main_failed:
        sys.stderr.write("main tier unavailable, exit 3\n")
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())