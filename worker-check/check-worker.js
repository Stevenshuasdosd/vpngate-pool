/**
 * FreeStack L2 · VPN Gate SSTP(443) 可达性检测端
 * ============================================================
 * 部署: Cloudflare Workers（免费版即可），直接粘贴本文件到 Worker 编辑器后部署。
 * 作用: 供 vpngate_check.py 的 CHECK_WORKER 模式调用，从 Cloudflare 边缘网络视角
 *       检测 VPN Gate 节点 443 端口是否可达。
 *       为什么用 CF 视角？因为 edgetunnel 本身跑在 CF Workers 上，它作为 SSTP
 *       客户端连接 VPN Gate 节点时走的正是 CF 的出网 —— 这里的检测结果，
 *       比 GitHub Actions runner 的直连检测更贴近 edgetunnel 链式代理的实际可用性。
 *
 * 请求: GET /check?sstp=vpn:vpn@HOST
 *       （HOST 为待测节点 IP 或域名；sstp 参数格式兼容小何博客的调用约定）
 * 返回: {"host":..., "ok":true/false, "ms":..., ...}
 *       - ok:true  + via:"tls-handshake"   → 收到 HTTP 响应，443 可达且完成 TLS 握手
 *       - ok:true  + via:"tls-cert-seen"   → 证书校验失败但服务器已返回证书，
 *                                            同样证明 443 端口可达且有 TLS 服务在监听
 *                                            （直连 IP 时证书 CN/SAN 必然对不上，这是预期内的）
 *       - ok:false                          → 连接拒绝 / 超时 / DNS 失败
 *
 * 额度: 每次 Actions 运行约发起 100~200 次检测（并发 32），每天 8 次 ≈ 1600 请求/天，
 *       远低于 Workers 免费版 10 万请求/天。
 */

const TIMEOUT_MS = 9000;

export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname !== "/check") {
      return json({ error: "usage: /check?sstp=vpn:vpn@HOST" }, 400);
    }

    // 兼容格式: sstp=vpn:vpn@HOST，取 @ 后面的主机部分
    const sstp = url.searchParams.get("sstp") || "";
    const m = sstp.match(/@([^:@/\s?#]+)/);
    const host = m ? m[1] : "";
    if (!host) {
      return json({ host: "", ok: false, error: "bad host, expect /check?sstp=vpn:vpn@HOST" }, 400);
    }

    const t0 = Date.now();
    try {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort("timeout"), TIMEOUT_MS);
      let resp;
      try {
        // SSTP 走 443/HTTPS：只要能完成 TLS 握手并拿到 HTTP 响应（含 4xx/5xx），
        // 即视为 SSTP 可达候选。真正的 SSTP 握手由 edgetunnel 客户端完成。
        resp = await fetch(`https://${host}/`, {
          method: "GET",
          redirect: "manual",
          signal: ctrl.signal,
          headers: { "User-Agent": "FreeStack-check/1.0" },
        });
      } finally {
        clearTimeout(timer);
      }
      try { await resp.arrayBuffer(); } catch (_) { /* 忽略 body 读取错误 */ }
      return json({ host, ok: true, ms: Date.now() - t0, http_status: resp.status, via: "tls-handshake" });
    } catch (e) {
      const msg = String((e && e.message) || e);
      // 证书错误（直连 IP 时 CN/SAN 对不上）同样证明：TCP 建连成功 + 对端完成了 TLS 握手
      if (/certificate|cert|SSL|TLS/i.test(msg)) {
        return json({ host, ok: true, ms: Date.now() - t0, via: "tls-cert-seen", detail: msg.slice(0, 80) });
      }
      return json({ host, ok: false, ms: Date.now() - t0, error: msg.slice(0, 120) });
    }
  },
};

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "access-control-allow-origin": "*",
      "cache-control": "no-store",
    },
  });
}
