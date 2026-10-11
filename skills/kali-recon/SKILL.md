---
name: kali-recon
description: 用本机 Kali 工具链（amass/nmap/masscan/httpx/nuclei/gobuster/ffuf/whatweb/wafw00f）替代 ScopeSentry 做资产测绘与漏扫，结果直接用 insert_assets/report_finding 入库。用户提到资产收集、子域名、端口扫描、指纹识别、目录扫描、漏洞扫描且未指定 ScopeSentry 时使用。
---

# Kali 本机工具链资产测绘（ScopeSentry 替代方案）

**前提：目标已获授权测试。** 本 skill 把 [ScopeSentry](../scopesentry/SKILL.md) 的流水线模块
（`SubdomainScan → PortScan → PortFingerprint → AssetMapping → URLScan/WebCrawler → DirScan →
VulnerabilityScan`）替换成 Kali 本机命令行工具的等价组合，不依赖外部平台/MCP/数据库——过程全部跑在
本机 Bash，产物直接写入 ARTEX 自己的资产库（`insert_assets`）和漏洞库（`report_finding`）。

**和 ScopeSentry 的本质差异**：ScopeSentry 是分布式平台，任务跑在远程节点、结果存在它自己的
Mongo 里，要用 `list_assets`/`count_assets` 等 MCP 工具查询。这里没有远程节点、没有独立存储——
Kali 工具在**当前 agent 所在机器**单机跑，输出由 agent 直接解析后用 ARTEX 原生的 `insert_assets`
登记，查询时用 ARTEX 自己的 `list_assets`（DSL 见该工具 description），**不要混用 ScopeSentry 的
search 语法**。单机意味着没有分布式节流——大批量目标要自己控制并发/批次（见「并发与批次」）。

---

## 模块映射表

| ScopeSentry 模块 | 对应 Kali 工具 | 典型命令 |
|---|---|---|
| `SubdomainScan`（子域名收集） | `amass enum` | `amass enum -passive -d example.com -o subs.txt` |
| `SubdomainSecurity`（子域接管检测） | 无直接等价工具，可用 `httpx` 读取 CNAME+响应特征辅助判断，或跳过 | — |
| `PortScanPreparation`/`PortScan`（端口扫描） | `nmap` / `masscan` | 大范围先 `masscan` 粗扫开放端口，再 `nmap -sV` 精细识别 |
| `PortFingerprint`（服务指纹） | `nmap -sV -sC`、`whatweb` | — |
| `AssetMapping`/`URLScan`（站点测绘/URL 存活） | `httpx` | `httpx -l subs.txt -title -tech-detect -status-code -o live.json -json` |
| `WebCrawler`（爬虫） | 本机无 katana/gospider 时用 `httpx` 的基本抓取 + agent 自行 `curl`/浏览器 skill 补充 | — |
| `DirScan`（目录扫描） | `gobuster dir` / `ffuf` | `gobuster dir -u https://target -w <wordlist> -o dirscan.txt` |
| `VulnerabilityScan`（漏洞扫描） | `nuclei` | `nuclei -l live.json -json-export nuclei.json` |
| （WAF 识别，ScopeSentry 无单独模块） | `wafw00f` | `wafw00f https://target` |

未安装的可选增强工具（Kali 仓库有包，默认未装可按需 `apt install`）：`subfinder`、`naabu`、`dnsx`。
不装也不影响本 skill 跑通——上表全部用已安装工具即可覆盖全流程。

---

## 两阶段流程（对应 ScopeSentry §3.3 的分阶段建议）

**原因同 ScopeSentry 文档**：子域名收集和后续模块（端口/指纹/漏扫）耦合在一次全流程里，目标一多会
拖慢、出错率高、不好断点重试。单机场景下分两阶段更利于分别检查中间产物、按需重跑失败的一步。

### 阶段一：子域名收集与存活探测

```bash
# 1. 子域名收集（被动，不直接碰目标，适合先摸底）
amass enum -passive -d example.com -o subs.txt

# 2. 存活 + 基础指纹（HTTP/HTTPS 都探）
httpx -l subs.txt -title -tech-detect -status-code -follow-redirects \
  -json -o live.json

# 3. 可选：WAF 识别（遇状态码异常/指纹不明再按需跑，不必对全部资产跑）
wafw00f https://sub.example.com
```

读取 `live.json`（每行一个 JSON 对象，含 `url`/`status_code`/`title`/`tech`/`a` 记录等字段），
为每条存活资产调用 `insert_assets`：
- 域名本身 → `type: subdomain`（`domain`、可选 `record_type`/`record_value`）
- 有 HTTP 响应 → 额外一条 `type: service`（`url`、`status_code`、`page_title`、`technologies`）

### 阶段二：端口扫描 + 漏洞扫描

对阶段一产出的 IP（或直接对根域名/IP 段）：

```bash
# 大范围先粗扫开放端口（比全端口 nmap 快很多）
masscan -p1-65535 --rate 1000 -oJ masscan.json <IP或CIDR>

# 对 masscan 发现的开放端口做服务/版本识别
nmap -sV -sC -p <masscan发现的端口> -oX nmap.xml <IP>

# 对已存活的 HTTP(S) 资产跑漏洞扫描
nuclei -l live.json -severity low,medium,high,critical -json-export nuclei.json
```

- `nmap`/`masscan` 结果 → `insert_assets` 的 `type: ip`，`open_ports` 填 `[{port, service}]`。
- `nuclei.json` 每条命中 → `report_finding`：`vulnclass` 取 nuclei 模板的 `template-id` 大类（如
  `exposed-panel`/`cve`/`misconfiguration`），`severity` 直接用 nuclei 的 `info.severity`
  （critical/high/medium/low，nuclei 的 `info` 也可能没有 low 以下级别，按需忽略），
  `evidence` 填 `matched-at` + 原始响应片段，`asset_ids` 关联对应的 `service`/`ip` 资产 id。

### 目录扫描（按需，不必对所有站点都跑）

只对明确要深入的站点跑，避免噪音：

```bash
gobuster dir -u https://target -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -o dirscan.txt -t 20
```

命中的敏感路径（如管理后台、备份文件）视情况登记为 `endpoint` 资产或直接走 `report_finding`
（如暴露 `.git`/`.env` 这类属于确认风险的，按漏洞上报；单纯目录结构发现按资产登记）。

---

## 并发与批次（ScopeSentry 靠分布式节点，这里靠自己控速）

- `amass`/`httpx`/`nuclei` 默认自带限速参数（`-rate-limit`、`-c` 等），**目标多时主动调低并发**，
  不要指望单机扛住 ScopeSentry 那种多节点吞吐。
- 根域名很多时，按「阶段一全部跑完 → 落盘 subs.txt/live.json → 阶段二再分批跑」的顺序处理，
  不要边收集边扫端口/漏洞，否则一个目标卡住会堵塞整条流水线（这点和 ScopeSentry 文档里
  "根域名作为单目标分发，子域名应作为独立目标并行"的原因一致，只是这里没有调度器帮你拆，
  需要 agent 自己先落盘子域名再分批处理）。
- `masscan` 需要较高权限（通常要 root/`CAP_NET_RAW`），当前用户跑不了就退回 `nmap -Pn -p-`
  做端口扫描（慢但不需要额外权限）。

---

## 与 ARTEX 原生工具对接

| 产出 | 登记方式 |
|---|---|
| 子域名 | `insert_assets` `type: subdomain` |
| IP + 开放端口 | `insert_assets` `type: ip`，`open_ports: [{port, service}]` |
| HTTP(S) 站点 | `insert_assets` `type: service`（`url` 必填，`technologies`/`status_code`/`page_title` 可选） |
| 非 HTTP 服务（如裸端口 ssh/mysql） | `insert_assets` `type: service`，填 `service_name`+`port`（无 `url`） |
| 敏感目录/接口 | `insert_assets` `type: endpoint`（`url`+`method`），或直接 `report_finding` |
| 确认漏洞 | `report_finding`：`vulnclass`/`severity`/`summary`/`evidence`，关联 `asset_ids` |
| 查询已登记资产 | `list_assets`（DSL，见该工具 description，**不是** ScopeSentry 的 search/filter 语法） |
| 按公司归属资产范围 | `list_companies` 拿 `company_id`，app 类型资产登记时可显式关联 |

**不要**把 ScopeSentry 的 `search`/`filter` DSL、`project ObjectID`、`task 名称过滤` 等概念套到
`list_assets` 上——ARTEX 自己的查询语法在 `list_assets` 工具描述里，字段名也不同（如没有
`filter.project`，范围靠 `task_id`/`company_id` 隐式限定）。

