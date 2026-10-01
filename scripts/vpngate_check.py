#!/usr/bin/env python3
"""VPN Gate 免费节点抓取 + SSTP(443) 可达性检测 + Pages 产物生成.

设计说明（融合方案 L2 备用层）:
  - 数据源: https://www.vpngate.net/api/iphone/ （筑波大学公开 API, CSV, 末字段为 base64 的 OpenVPN 配置）
  - 检测: 对每个节点 IP 的 443 端口做 TCP 连通 + TLS 握手（VPN Gate 的 SSTP 走 443/HTTPS,
    TLS 能握手即视为 SSTP 可达候选；真正的 SSTP 握手由客户端/agent 完成）
  - 产物: public/nodes.json（给 KKK 面板/agent 消费）, public/hosts.txt,
    public/ovpn/*.ovpn（TopN, 可直接导入客户端或喂给 agent 做降级隧道）, public/index.html
  - 定时: 由 .github/workflows/vpngate.yml 每 3 小时触发（Actions 免费额度安全线内）

本地测试: python3 scripts/vpngate_check.py [--limit N] [--top-ovpn N]
"""

from __future__ import annotations

import argparse
import base64
import csv
import datetime
import io
import json
import os
import socket
import ssl
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

API_URL = "https://www.vpngate.net/api/iphone/"
HEADER_PREFIX = "#HostName,IP,Score,"
CONNECT_TIMEOUT = 8.0
TLS_TIMEOUT = 10.0
WORKERS = 32

# CHECK_WORKER 模式（可选，推荐）: 填入自己部署的 check Worker 地址后，
# 检测走 Cloudflare 边缘视角（与 edgetunnel 实际出网一致），形如:
#   https://xxx.workers.dev/check?sstp=vpn:vpn@
# 不填则 fallback 到 runner 直连检测（TCP+TLS）。
# 兼容小何博客的 env 约定: CHECK_WORKER / CHECK_CONCURRENCY / CHECK_TIMEOUT
CHECK_WORKER = os.environ.get("CHECK_WORKER", "").strip()
CHECK_CONCURRENCY = int(os.environ.get("CHECK_CONCURRENCY", "32") or 32)
CHECK_TIMEOUT = float(os.environ.get("CHECK_TIMEOUT", "90") or 90)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PUBLIC = os.path.join(ROOT, "public")
OVPN_DIR = os.path.join(PUBLIC, "ovpn")


def fetch_api(retries: int = 3) -> str:
    last_err = None
    for i in range(retries):
        try:
            req = urllib.request.Request(
                API_URL, headers={"User-Agent": "FreeStack-vpngate-check/1.0"}
            )
            with urllib.request.urlopen(req, timeout=30) as r:
                text = r.read().decode("utf-8", errors="replace")
            if HEADER_PREFIX not in text:
                raise ValueError("API 返回内容缺少预期表头, 格式可能已变更")
            return text
        except Exception as e:  # noqa: BLE001
            last_err = e
            time.sleep(2 * (i + 1))
    raise RuntimeError(f"抓取 VPN Gate API 失败(重试{retries}次): {last_err}")


def parse_rows(text: str) -> list[dict]:
    """稳健解析: 先从右切出末字段(base64 无逗号), 再从左切 13 刀, Message 内嵌逗号不影响."""
    rows: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("*") or line.startswith("#"):
            continue
        try:
            head, cfg_b64 = line.rsplit(",", 1)
        except ValueError:
            continue
        parts = head.split(",", 13)
        if len(parts) < 14:
            continue
        try:
            base64.b64decode(cfg_b64.strip(), validate=True)
        except Exception:  # noqa: BLE001
            continue  # 末字段不是合法 base64, 跳过脏行
        rows.append(
            {
                "host": parts[0],
                "ip": parts[1],
                "score": _to_int(parts[2]),
                "ping_ms": _to_int(parts[3]),
                "speed_bps": _to_int(parts[4]),
                "country_long": parts[5],
                "country_short": parts[6],
                "sessions": _to_int(parts[7]),
                "uptime_ms": _to_int(parts[8]),
                "total_users": _to_int(parts[9]),
                "total_traffic": _to_int(parts[10]),
                "log_type": parts[11],
                "operator": parts[12],
                "message": parts[13],
                "ovpn_b64": cfg_b64.strip(),
            }
        )
    # 同 IP 去重, 保留 Score 高的
    best: dict[str, dict] = {}
    for r in rows:
        if r["ip"] not in best or r["score"] > best[r["ip"]]["score"]:
            best[r["ip"]] = r
    return list(best.values())


def _to_int(s: str) -> int:
    try:
        return int(s)
    except (ValueError, TypeError):
        return 0


def check_host(ip: str) -> tuple[bool, float, bool]:
    """返回 (tcp_ok, 延迟ms, tls_ok). 443 是 VPN Gate SSTP 端口."""
    t0 = time.monotonic()
    try:
        sock = socket.create_connection((ip, 443), timeout=CONNECT_TIMEOUT)
    except OSError:
        return False, -1.0, False
    latency = (time.monotonic() - t0) * 1000
    tls_ok = False
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
            ssock.settimeout(TLS_TIMEOUT)
            ssock.do_handshake()
            tls_ok = True
    except (OSError, ssl.SSLError):
        tls_ok = False
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return True, round(latency, 1), tls_ok


def check_via_worker(ip: str) -> tuple[bool, float, bool]:
    """经 CHECK_WORKER（Cloudflare 边缘）检测。返回 (ok, 延迟ms, tls_ok).

    Worker 本身已做 TLS 握手探测，ok=true 即视为 SSTP 可达候选（tls_ok=True）。
    返回的 ms 是 CF 边缘到节点的延迟 —— 这正是 edgetunnel 链式代理的实际视角。
    """
    url = f"{CHECK_WORKER}{ip}"
    t0 = time.monotonic()
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "FreeStack-vpngate-check/1.0"}
        )
        with urllib.request.urlopen(req, timeout=CHECK_TIMEOUT) as r:
            data = json.loads(r.read().decode("utf-8", errors="replace"))
        if not data.get("ok"):
            return False, -1.0, False
        latency = data.get("ms")
        if not isinstance(latency, (int, float)) or latency < 0:
            latency = (time.monotonic() - t0) * 1000
        return True, round(float(latency), 1), True
    except Exception:  # noqa: BLE001
        return False, -1.0, False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0, help="本地调试: 只测前 N 个节点")
    ap.add_argument("--top-ovpn", type=int, default=30, help="输出 TopN 的 .ovpn 配置")
    args = ap.parse_args()

    print("[1/4] 抓取 VPN Gate API...", flush=True)
    rows = parse_rows(fetch_api())
    print(f"      解析到 {len(rows)} 个去重节点", flush=True)
    if args.limit:
        rows = rows[: args.limit]

    print(f"[2/4] 检测 443 端口可达性...", flush=True)
    if CHECK_WORKER:
        # CF 边缘视角：与 edgetunnel 实际出网一致，优先推荐
        print(f"      模式: CHECK_WORKER（CF 边缘视角, 并发 {CHECK_CONCURRENCY}）", flush=True)
        with ThreadPoolExecutor(max_workers=CHECK_CONCURRENCY) as ex:
            results = list(ex.map(check_via_worker, [r["ip"] for r in rows]))
    else:
        # runner 直连 fallback：本地/CI 无需额外部署即可用
        print(f"      模式: runner 直连 TCP+TLS（并发 {WORKERS}，未配置 CHECK_WORKER）", flush=True)
        with ThreadPoolExecutor(max_workers=WORKERS) as ex:
            results = list(ex.map(check_host, [r["ip"] for r in rows]))
    for r, (ok, lat, tls) in zip(rows, results):
        r["tcp_ok"], r["latency_ms"], r["tls_ok"] = ok, lat, tls
    ok_rows = [r for r in rows if r["tcp_ok"]]
    print(f"      可达 {len(ok_rows)}/{len(rows)} (其中 TLS 握手成功 {sum(1 for r in ok_rows if r['tls_ok'])})", flush=True)

    # 排序: TLS 成功优先, 延迟低优先, Score 高优先
    ok_rows.sort(key=lambda r: (not r["tls_ok"], r["latency_ms"], -r["score"]))

    print("[3/4] 生成产物...", flush=True)
    os.makedirs(OVPN_DIR, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    nodes = [
        {
            "host": r["host"],
            "ip": r["ip"],
            "country_long": r["country_long"],
            "country_short": r["country_short"],
            "ping_ms": r["ping_ms"],
            "score": r["score"],
            "latency_ms": r["latency_ms"],
            "tls_ok": r["tls_ok"],
            "sessions": r["sessions"],
            "uptime_hours": round(r["uptime_ms"] / 3600000, 1),
        }
        for r in ok_rows
    ]
    detect_mode = "check_worker_cf_edge" if CHECK_WORKER else "runner_direct_tcp_tls"
    with open(os.path.join(PUBLIC, "nodes.json"), "w", encoding="utf-8") as f:
        json.dump(
            {
                "updated_utc": now,
                "source": API_URL,
                "detect_mode": detect_mode,
                "total_listed": len(rows),
                "reachable": len(ok_rows),
                "note": "latency_ms 为检测机到节点 443 端口的延迟; tls_ok 表示 443 可完成 TLS 握手（SSTP 候选）。check_worker_cf_edge 为 CF 边缘视角（与 edgetunnel 出网一致）。",
                "nodes": nodes,
            },
            f,
            ensure_ascii=False,
            indent=1,
        )
    with open(os.path.join(PUBLIC, "hosts.txt"), "w", encoding="utf-8") as f:
        f.write(f"# VPN Gate 可达节点（SSTP 443）, 更新: {now} UTC, 共 {len(ok_rows)} 个\n")
        for r in ok_rows:
            flag = "TLS" if r["tls_ok"] else "TCP"
            f.write(f"{r['ip']}:443  # {r['country_short']} {r['latency_ms']}ms [{flag}] {r['host']}\n")

    # edgetunnel 链式代理订阅源：每行一个 vless 占位链接，备注嵌入 $sstp:// 标记。
    # 用户在 edgetunnel 后台本地IP库/ADD.txt 里加一行本文件的 URL，
    # edgetunnel 每次生成订阅时实时拉取，自动替换占位 UUID/域名为真实值，
    # 并把 $sstp:// 解析为 SSTP 链式代理（账号密码均为 vpn）。
    # 流量路径: 客户端 → edgetunnel(CF) → SSTP → VPN Gate 节点 → 互联网
    with open(os.path.join(PUBLIC, "edgetunnel-nodes.txt"), "w", encoding="utf-8") as f:
        # 注意: 文件必须以 vless:// 行开头，不能加 # 注释头。
        # edgetunnel 的请求优选API用 content.split('#')[0].includes('://') 判定是否为节点LINK，
        # 行首的 # 注释会让整份文件被误判为纯IP列表，导致订阅为空。
        for r in ok_rows:
            remark = f"{r['country_short']}-{r['latency_ms']}ms"
            f.write(
                "vless://00000000-0000-4000-8000-000000000000@example.com:443"
                f"#{remark}$sstp://vpn:vpn@{r['ip']}:443\n"
            )

    for f_ in os.listdir(OVPN_DIR):
        if f_.endswith(".ovpn"):
            os.remove(os.path.join(OVPN_DIR, f_))
    for r in ok_rows[: args.top_ovpn]:
        safe_ip = r["ip"].replace(".", "_")
        with open(os.path.join(OVPN_DIR, f"{safe_ip}.ovpn"), "wb") as f:
            f.write(base64.b64decode(r["ovpn_b64"]))

    print("[4/4] 生成 index.html...", flush=True)
    write_index(len(rows), len(ok_rows), now)
    print(f"完成: {len(ok_rows)} 可达 / {len(rows)} 列表, Top{args.top_ovpn} ovpn 已输出", flush=True)
    return 0


def write_index(total: int, ok: int, now: str) -> None:
    html = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VPN Gate 备用节点池 · FreeStack L2</title>
<style>
body{font-family:system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;background:#0f1420;color:#e6edf3;margin:0;padding:24px}
h1{font-size:20px;margin:0 0 4px}.sub{color:#8b98a9;font-size:13px;margin-bottom:16px}
input{background:#1a2233;border:1px solid #2c3a52;color:#e6edf3;border-radius:8px;padding:8px 12px;width:260px;margin-bottom:12px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{border-bottom:1px solid #223047;padding:8px 10px;text-align:left}
th{color:#8b98a9;font-weight:600}.ok{color:#3fb950}.warn{color:#d29922}
a{color:#58a6ff}.card{background:#161e2e;border:1px solid #223047;border-radius:12px;padding:16px;margin-bottom:16px}
</style></head><body>
<h1>VPN Gate 备用节点池 <span style="font-size:12px;color:#3fb950">● LIVE</span></h1>
<div class="sub">FreeStack L2 备用层 · 每 3 小时自动抓取 + SSTP(443) 可达性检测 ·
更新: __NOW__ UTC · 列表 __TOTAL__ / 可达 __OK__</div>
<div class="card"><input id="q" placeholder="筛选国家/地区代码, 如 JP / US" oninput="f()">
<table><thead><tr><th>#</th><th>IP</th><th>国家</th><th>延迟</th><th>TLS</th><th>Score</th><th>会话</th><th>ovpn</th></tr></thead>
<tbody id="tb"></tbody></table></div>
<div class="card" style="font-size:13px;color:#8b98a9">
<b style="color:#e6edf3">文件说明</b><br>
· <a href="nodes.json">nodes.json</a> — 机器可读全量节点（KKK 面板/agent 降级拉取用）<br>
· <a href="hosts.txt">hosts.txt</a> — 纯文本节点清单（一行一个, 可粘贴）<br>
· <a href="edgetunnel-nodes.txt">edgetunnel-nodes.txt</a> — <b style="color:#e6edf3">edgetunnel 链式代理订阅源</b>（把本文件 URL 填进 edgetunnel 后台本地IP库/ADD.txt, 订阅自动带 SSTP 链式代理, 详见部署指南）<br>
· <a href="ovpn/">ovpn/</a> — Top30 的 OpenVPN 配置（客户端直接导入 / agent 降级隧道）<br>
· 默认 SSTP 账号/密码均为 <code>vpn</code>；节点为志愿者分享, 质量波动属正常现象。
</div>
<script>
let N=[];
fetch("nodes.json").then(r=>r.json()).then(d=>{N=d.nodes;f()});
function f(){const q=document.getElementById("q").value.toUpperCase();
const tb=document.getElementById("tb");tb.innerHTML="";
N.filter(n=>!q||n.country_short.includes(q)||n.country_long.toUpperCase().includes(q)||n.ip.includes(q))
.forEach((n,i)=>{const tr=document.createElement("tr");
tr.innerHTML=`<td>${i+1}</td><td><code>${n.ip}</code></td><td>${n.country_short} ${n.country_long}</td>
<td>${n.latency_ms}ms</td><td class="${n.tls_ok?"ok":"warn"}">${n.tls_ok?"✓":"–"}</td>
<td>${n.score}</td><td>${n.sessions}</td>
<td>${i<30?`<a href="ovpn/${n.ip.replace(/\\./g,"_")}.ovpn">下载</a>`:"–"}</td>`;
tb.appendChild(tr);});}
</script></body></html>"""
    html = html.replace("__NOW__", now).replace("__TOTAL__", str(total)).replace("__OK__", str(ok))
    with open(os.path.join(PUBLIC, "index.html"), "w", encoding="utf-8") as f:
        f.write(html)


if __name__ == "__main__":
    sys.exit(main())
