#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_sub.py - turn a free-node aggregator into an account-safe sing-box subscription.
Output file name is literally "sub", so Hiddify names the profile "sub".

Rules
 1. keep only nodes with transport TLS AND certificate verification (tls.insecure -> dropped)
 2. drop plaintext nodes, legacy-cipher shadowsocks, bare http/socks proxies, Cloudflare WARP
 3. one node per exit host (many free nodes share a single abused IP)
 4. rank: VLESS-Reality first, then nodes close to CN
 5. no silent exit switching: selector default = first fixed node, AUTO (urltest) is last
 6. fail-safe: too few usable nodes -> non-zero exit, CI keeps the previous good file

兼容性提醒: Hiddify 用 Go 严格解析 sing-box JSON，未知字段会整份拒绝（实测
interrupt_override_count 会报 [SingboxParser] unmarshal error）。只写确定存在的字段。
"""
import json
import os
import sys
import time
import urllib.request

UP = "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main"
MAIN_URL = UP + "/output/singbox.json"
MANIFEST_URL = UP + "/output/manifest.json"
COUNTRY_URL = UP + "/output/by-country/singbox-{cc}.json"

ALLOWED = {"vless", "vmess", "trojan", "hysteria2", "tuic", "shadowsocks"}
AEAD_SS = ("aes-256-gcm", "aes-128-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305")
NEAR = {"JP": 6, "KR": 5, "SG": 5, "HK": 5, "TW": 5, "MO": 4, "MY": 4, "TH": 4, "VN": 4,
        "US": 3, "CA": 2, "AU": 2}
MAX_NODES = int(os.environ.get("MAX_NODES", "200"))
MIN_NODES_OK = int(os.environ.get("MIN_NODES_OK", "25"))
ONLY_CC = {c.strip().upper() for c in os.environ.get("ONLY_CC", "").split(",") if c.strip()}
# 只反查节点数达到该数量的国家分片：既省下载，又足够覆盖 99% 的存活节点
CC_MIN_COUNT = int(os.environ.get("CC_MIN_COUNT", "30"))
NO_COUNTRIES = "--no-countries" in sys.argv


def fetch(url, timeout=90, retries=3):
    last = None
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(2 + 3 * i)
    raise RuntimeError("fetch failed: %s (%s)" % (url, last))


def safe_node(o):
    t = o.get("type")
    if t not in ALLOWED:
        return False, "type_not_allowed"
    if not o.get("server") or not o.get("server_port"):
        return False, "no_server"
    tls = o.get("tls") or {}
    if t == "shadowsocks":
        # SS 自带加密与认证，不额外要求 TLS，但必须是 AEAD 且不能关掉证书校验
        if not o.get("password"):
            return False, "no_password"
        if not str(o.get("method", "")).lower().startswith(AEAD_SS):
            return False, "weak_cipher"
    else:
        if not tls.get("enabled"):
            return False, "plaintext"
    if tls.get("insecure"):
        return False, "insecure_cert"
    if t == "tuic":
        if not (o.get("uuid") and o.get("password")):
            return False, "no_creds"
    elif not (o.get("uuid") or o.get("password")):
        return False, "no_creds"
    real = tls.get("reality")
    if real is not None and not real.get("public_key"):
        return False, "broken_reality"
    return True, ""


def country_lookup():
    m = {}
    if NO_COUNTRIES:
        return m, []
    try:
        mani = fetch(MANIFEST_URL, timeout=45)
        coll = mani.get("collections", {})
        pairs = []
        for k, v in coll.items():
            if k.startswith("country/") and isinstance(v, int):
                cc = k.split("/")[1]
                if cc not in ("T1", "XX") and v >= CC_MIN_COUNT:
                    pairs.append((v, cc))
        codes = [cc for _, cc in sorted(pairs, reverse=True)]
    except Exception as e:  # noqa: BLE001
        sys.stderr.write("manifest failed, no country labels: %s\n" % e)
        return m, []
    for cc in codes:
        try:
            d = fetch(COUNTRY_URL.format(cc=cc), timeout=45)
        except Exception:  # noqa: BLE001
            continue
        for o in d.get("outbounds", []):
            tg = o.get("tag")
            if tg and tg not in m:
                m[tg] = cc
    return m, codes


def main():
    if "--main-file" in sys.argv:
        with open(sys.argv[sys.argv.index("--main-file") + 1], encoding="utf-8") as f:
            data = json.load(f)
    else:
        data = fetch(MAIN_URL)
    cmap, ccodes = country_lookup()

    nodes = [o for o in data.get("outbounds", []) if o.get("server")]
    dropped = {}

    def drop(why):
        dropped[why] = dropped.get(why, 0) + 1

    kept = []
    for o in nodes:
        ok, why = safe_node(o)
        if ok:
            kept.append(o)
        else:
            drop(why)

    seen, uniq = set(), []
    for o in kept:
        host = str(o["server"]).lower().strip("[]")
        if host in seen:
            drop("dup_exit")
            continue
        seen.add(host)
        uniq.append(o)

    if ONLY_CC:
        uniq = [o for o in uniq if cmap.get(o.get("tag")) in ONLY_CC]

    def rank(o):
        tls = o.get("tls") or {}
        if tls.get("reality"):
            p = 3
        elif o.get("type") in ("trojan", "vless", "hysteria2"):
            p = 2
        else:
            p = 1
        return NEAR.get(cmap.get(o.get("tag"), ""), 0) * 10 + p

    uniq.sort(key=rank, reverse=True)
    final = uniq[:MAX_NODES]
    if len(final) < MIN_NODES_OK:
        sys.stderr.write("only %d usable nodes (<%d), upstream looks broken; not writing output\n"
                         % (len(final), MIN_NODES_OK))
        return 3

    out, seq, ccs = [], {}, []
    for o in final:
        t = o["type"]
        cc = cmap.get(o.get("tag"), "??")
        seq[t] = seq.get(t, 0) + 1
        o.pop("comments", None)
        o["tag"] = "%s %s-%02d" % (cc, t, seq[t])
        out.append(o)
        ccs.append(cc)

    tags = [o["tag"] for o in out]
    cfg = {
        "outbounds": [
            {"tag": "select", "type": "selector", "outbounds": [tags[0]] + tags[1:] + ["AUTO"]},
            {"tag": "AUTO", "type": "urltest", "outbounds": tags,
             "url": "https://www.gstatic.com/generate_204",
             "interval": "15m", "tolerance": 120},
            {"tag": "direct", "type": "direct"},
        ] + out,
        "route": {"final": "select"},
    }
    with open(os.environ.get("OUT_FILE", "sub"), "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=1)

    stats = {
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "upstream": MAIN_URL,
        "upstream_nodes": len(nodes),
        "tls_verified": len(kept),
        "unique_exits": len(seen),
        "published": len(final),
        "country_shards_used": len(ccodes),
        "dropped": dropped,
        "protocols": {},
        "countries": {},
        "note": "selector default is a FIXED node; AUTO(urltest) changes exit ip - do not use it for google logins",
    }
    for o, cc in zip(out, ccs):
        stats["protocols"][o["type"]] = stats["protocols"].get(o["type"], 0) + 1
        stats["countries"][cc] = stats["countries"].get(cc, 0) + 1
    with open("sub-stats.json", "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
