# VPN Gate 备用节点池 · 用户操作手册（终版）

> FreeStack L2 备用层。每 3 小时自动抓取 VPN Gate（筑波大学公开免费 VPN 项目）
> 节点，做 SSTP(443) 可达性检测，发布到 GitHub Pages。
> 预计操作时间：约 15 分钟（不含等待部署）。

---

## 步骤一：部署 check Worker（推荐，可选）

这是检测端：从 Cloudflare 边缘网络视角测节点 443 是否可达。
为什么推荐？因为 edgetunnel 本身跑在 CF 上，它连 VPN Gate 走的正是 CF 的出网——
这个视角的检测结果最贴近链式代理的真实可用性。

1. 登录 Cloudflare → **Workers 和 Pages** → **创建应用程序** → **创建 Worker** → 部署。
2. 点 **编辑代码**，清空，把本目录 `worker-check/check-worker.js` 的内容完整粘贴 → **部署**。
3. 记下域名，如 `https://vpngate-check-abc.xxxx.workers.dev`。
   检测地址格式为：`https://vpngate-check-abc.xxxx.workers.dev/check?sstp=vpn:vpn@`
   （注意末尾保留 `sstp=vpn:vpn@`，后面会自动拼接节点 IP）

> 跳过此步也行：不填 CHECK_WORKER 时自动用 runner 直连检测，无需额外部署。
> 但检测视角是 GitHub 机房网络，略逊于 CF 视角。

---

## 步骤二：新建 GitHub 仓库并上传代码

1. GitHub → **New repository**，名字如 `vpngate-pool`，**必须选 Public**，
   勾选 Add a README file → Create。
2. 在仓库主页点 **Add file → Upload files**，把本目录的以下内容拖进去：
   - `scripts/`（整个目录，含 `vpngate_check.py`）
   - `worker-check/`（整个目录，留档用，不强制）
   - `.gitignore`
   - `README.md`（本文件）
   
   → **Commit changes**。
3. ⚠️ 工作流文件必须手动创建（网页端传不了 `.github/` 开头的路径）：
   **Add file → Create new file**，文件名框输入 `.github/workflows/vpngate.yml`
   （每输一个 `/` 会自动建目录），把本目录 `.github/workflows/vpngate.yml`
   的内容完整粘贴 → **Commit changes**。

---

## 步骤三：填入 CHECK_WORKER（做完步骤一才有）

在仓库里打开 `.github/workflows/vpngate.yml` → 点 ✏️ 编辑 →
找到 `env:` 下的 `CHECK_WORKER: ""`，填入步骤一的检测地址：

```yaml
CHECK_WORKER: "https://vpngate-check-abc.xxxx.workers.dev/check?sstp=vpn:vpn@"
```

→ **Commit changes**。`CHECK_CONCURRENCY: "32"` 和 `CHECK_TIMEOUT: "90"` 不用动。

---

## 步骤四：开 Actions 权限与 Pages

1. 仓库 **Settings** → **Actions** → **General** → **Workflow permissions**
   → 选 **Read and write permissions** → **Save**。
2. 仓库 **Settings** → **Pages** → **Build and deployment**
   → Source 选 **GitHub Actions**。

---

## 步骤五：手动跑一次，验收

1. 仓库顶部 **Actions** → 左侧 **VPN Gate Node Check** →
   右侧 **Run workflow** → 绿色 **Run workflow**。
2. 等 2~5 分钟，出现绿勾 ✅ 即成功。
3. 拿到地址（把 `<用户名>` `<仓库名>` 换成你的）：
   - 展示页：`https://<用户名>.github.io/<仓库名>/`
   - 机器可读：`https://<用户名>.github.io/<仓库名>/nodes.json`
   - 纯文本：`https://<用户名>.github.io/<仓库名>/hosts.txt`
   - **edgetunnel 订阅源**：`https://<用户名>.github.io/<仓库名>/edgetunnel-nodes.txt`

之后每 3 小时自动运行，你什么都不用管。

---

## 步骤六：接到 edgetunnel（备用入口）

详见 `../edgetunnel/部署指南.md`。一句话操作：
在 edgetunnel 后台的**本地IP库 / ADD.txt** 里加一行：

```
https://<用户名>.github.io/<仓库名>/edgetunnel-nodes.txt
```

edgetunnel 每次生成订阅时实时拉取，自动把 `$sstp://` 解析为 SSTP 链式代理。
客户端订阅 edgetunnel 的 `/sub` 即可使用。

---

## 产物说明

| 产物 | 说明 | 消费者 |
|------|------|--------|
| `index.html` | 可视化面板（延迟/国家筛选） | 人工查看 |
| `nodes.json` | 机器可读全量节点（含 `detect_mode`/`latency_ms`/`tls_ok`） | KKK 面板 / agent 降级拉取 |
| `hosts.txt` | 纯文本 `IP:443` 清单 | 手动粘贴 |
| `edgetunnel-nodes.txt` | edgetunnel 链式代理订阅源 | edgetunnel 后台（一次配置，自动更新） |
| `ovpn/` | Top30 的 OpenVPN 配置 | 客户端直接导入 / agent 降级隧道 |

默认 SSTP 账号密码均为 `vpn`。

---

## 定时频率说明（重要）

cron 为 `0 */3 * * *`（每 3 小时）。**不要改成 30 分钟**：
每 30 分钟 = 每月 1440 次 × 每次约 3 分钟 ≈ 4320 分钟，
免费额度只有 2000 分钟/月，会被打爆。
每 3 小时 = 每月约 240 次 ≈ 720 分钟，安全。

---

## 排障

| 现象 | 处理 |
|------|------|
| Actions 红叉 | 点进失败的 run 看日志；常见是 API 抓取超时，重跑一次即可 |
| Pages 404 | 确认 Settings → Pages → Source 已选 GitHub Actions；确认 Actions 有绿勾 |
| 订阅是空的 | 检查 `edgetunnel-nodes.txt` URL 浏览器能否打开；检查 Actions 是否正常运行 |
| 节点连不上 | VPN Gate 节点来来去去是常态，更新订阅即可；去展示页按国家筛选 |
| 想换检测模式 | `CHECK_WORKER` 留空 = runner 直连；填入地址 = CF 边缘视角 |
