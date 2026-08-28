#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_sub.py - one upstream, several safe sing-box subscription tiers.

一次抓取，多档输出（文件名 = Hiddify 里的配置名，故不能带扩展名/查询串）：
  sub        全量优选（默认档）
  sub-asia   日韩新港台+东南亚，延迟低，账号操作首选
  sub-us     美加，看美区内容
  sub-eu     欧洲，备胎

安全规则（对所有档位）
 1. 只保留传输层 TLS 且强制校验证书（tls.insecure 剔除：防对 accounts.google.com 中间人）
 2. 剔除明文、弱加密 shadowsocks、裸 http/socks 代理、Cloudflare WARP
 3. 同一出口 host 只留 1 个节点
 4. 排序 VLESS-Reality 优先 + 近华优先
 5. selector 第一项是固定节点，AUTO(urltest) 放最后，不自动跳出口

兼容性: Hiddify 用 Go 严格解析 sing-box JSON，未知字段整份拒绝（实测
interrupt_override_count 报 [SingboxParser] unmarshal error）。只写确定存在的字段。
"""
import copy
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
ASIA = {"JP", "KR", "SG", "HK", "TW", "MO", "MY", "TH", "VN", "PH", "ID", "AU", "NZ", "IN"}
AMER = {"US", "CA"}
EURO = {"GB", "DE", "NL", "FR", "IT", "ES", "SE", "NO", "FI", "DK", "PL", "EE", "LT", "LV",
        "AT", "CH", "IE", "CZ", "BE", "PT", "GR", "RO", "UA", "HU", "SK", "HR", "BG", "IS"}

VARIANTS = [
    ("sub", None, int(os.environ.get("MAX_NODES", "200")), 25),
    ("sub-asia", ASIA, int(os.environ.get("MAX_ASIA", "120")), 8),
    ("sub-us", AMER, int(os.environ.get("MAX_US", "120")), 8),
    ("sub-eu", EURO, int(os.environ.get("MAX_EU", "120")), 8),
]
ONLY_CC = {c.strip().upper() for c in os.environ.get("ONLY_CC", "").split(",") if c.strip()}
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
        if not o.get("password"):
            return False, "no_password"
        if not str(o.get("method", "")).lower().startswith(AEAD_SS):
            return False, "weak_cipher"
    elif not tls.get("enabled"):
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
        coll = fetch(MANIFEST_URL, timeout=45).get("collections", {})
        pairs = [(v, k.split("/")[1]) for k, v in coll.items()
                 if k.startswith("country/") and isinstance(v, int)
                 and k.split("/")[1] not in ("T1", "XX") and v >= CC_MIN_COUNT]
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


def render(nodes, ccs):
    out, seq = [], {}
    for o, cc in zip(nodes, ccs):
        o = copy.deepcopy(o)
        t = o["type"]
        seq[t] = seq.get(t, 0) + 1
        o.pop("comments", None)
        o["tag"] = "%s %s-%02d" % (cc, t, seq[t])
        out.append(o)
    tags = [o["tag"] for o in out]
    cfg = {
        "outbounds": [
            {"tag": "select", "type": "selector", "outbounds": [tags[0]] + tags[1:] + ["AUTO"]},
            {"tag": "AUTO", "type": "urltest", "outbounds": tags,
             "url": "https://www.gstatic.com/generate_204", "interval": "15m", "tolerance": 120},
            {"tag": "direct", "type": "direct"},
        ] + out,
        "route": {"final": "select"},
    }
    return cfg, out


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

    labels = [cmap.get(o.get("tag"), "??") for o in uniq]
    pairs = [(o, c) for o, c in zip(uniq, labels) if (not ONLY_CC) or c in ONLY_CC]

    def rank(o, cc):
        tls = o.get("tls") or {}
        if tls.get("reality"):
            p = 3
        elif o.get("type") in ("trojan", "vless", "hysteria2"):
            p = 2
        else:
            p = 1
        return NEAR.get(cc, 0) * 10 + p

    pairs.sort(key=lambda x: rank(x[0], x[1]), reverse=True)

    stats = {"generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
             "upstream": MAIN_URL, "upstream_nodes": len(nodes), "tls_verified": len(kept),
             "unique_exits": len(seen), "country_shards_used": len(ccodes),
             "dropped": dropped, "tiers": {},
             "note": "每档 selector 默认固定节点；AUTO 会换出口，Google 登录等敏感操作勿用 AUTO"}
    main_failed = False
    for name, ccset, cap, minimum in VARIANTS:
        sel = [(o, c) for o, c in pairs if ccset is None or c in ccset][:cap]
        if len(sel) < minimum:
            sys.stderr.write("tier %s 只有 %d 个(<%d)，本次跳过\n" % (name, len(sel), minimum))
            stats["tiers"][name] = {"skipped": True, "usable": len(sel)}
            if name == "sub":
                main_failed = True
            continue
        cfg, out = render([o for o, _ in sel], [c for _, c in sel])
        with open(name, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=1)
        pr, ct = {}, {}
        for o, (_, c) in zip(out, sel):
            pr[o["type"]] = pr.get(o["type"], 0) + 1
            ct[c] = ct.get(c, 0) + 1
        stats["tiers"][name] = {"nodes": len(out), "default": out[0]["tag"],
                                "protocols": pr, "countries": ct}

    with open("sub-stats.json", "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    if main_failed:
        sys.stderr.write("主档不可用，退出 3 让 CI 不覆盖\n")
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
