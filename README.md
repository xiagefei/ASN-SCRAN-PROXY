# Cloudflare 三网检测 / CF 优选 IP 工具 (cf_tri_net_detect)

针对 **Cloudflare CDN IP** 的「三网回程 + 优选」检测脚本。给定一个或多个 CIDR 网段，
自动完成 ICMP 延迟探测、Cloudflare 落地数据中心识别、多端口 TCP 延迟/抖动测量、三网回程
骨干线路判定（联通 9929/4837、电信 CN2/163、移动 CMIN2/CMI 等），并用 `iptest.exe`
对优选 IP 做**真实下载速度实测**，最终按 `IP:端口#国旗 | 城市 | ⬇️X.XMB/s | ❤️CF` 格式输出。

> 版本：**v1.0.0**（Apache License 2.0）

---

## 功能

1. **快速 ICMP RTT 探测** —— 并行 Ping 整个网段，得到平均/最小/最大延迟与丢包。
2. **Cloudflare 落地识别** —— 通过 `https://<ip>/cdn-cgi/trace` 获取 colo 代码 → 映射城市/国家。
3. **多端口 TCP RTT / 抖动** —— 测试 8 个常用端口，443 端口跑 4 轮取中位数 + jitter，识别稳定性。
4. **三网回程骨干判定** —— 基于 traceroute 跳数与 ASN 顺序/跳数，区分 CN2GIA/CN2GT/混合、
   9929/4837 前后关系、CMIN2/CMI，并给出置信度（已确认 / 混合）。
5. **综合评分与优选推荐** —— 加权评分（延迟 + 稳定 + 速度 + 路由 + 落地），给出 Top IP 与分运营商推荐。
6. **真实下载速度实测** —— 调用 `iptest.exe` 对优选 IP 做下载测速，**输出速度来自实测，而非回程推测**。

---

## 环境要求

- Python **3.8+**（脚本仅依赖标准库 + 可选 `maxminddb`）
- `maxminddb`：GeoLite2 离线库读取（**可选**，缺失时自动降级，仅影响 ASN 精确分类）

  ```bash
  pip install -r requirements.txt
  ```

- **外部二进制 / 数据文件**（置于脚本同目录）：
  | 文件 | 用途 | 来源 / 许可证 |
  |---|---|---|
  | `iptest.exe` | 下载速度实测 | oneclickvirt/iptest（Apache-2.0） |
  | `tracert` / `traceroute` | 路由追踪 | 操作系统自带 |
  | `GeoLite2-ASN.mmdb` | ASN 查询 | MaxMind GeoLite2（CC BY-SA 4.0） |
  | `GeoLite2-Country.mmdb` | 国家查询 | MaxMind GeoLite2（CC BY-SA 4.0） |

---

## 安装

```bash
git clone <repo> && cd <repo>
pip install -r requirements.txt
# 将 iptest.exe 与两个 GeoLite2 .mmdb 放到脚本同目录
```

---

## 用法

### 方式一：直接运行（CLI）

```bash
# 扫描单个 CIDR，输出优选 IP + iptest 实测速度
python cf_tri_net_detect.py 162.159.38.0/24 --ip-txt --iptest --csv-only

# 从文件读取多个 CIDR（一行一个，支持 # 注释）
python cf_tri_net_detect.py --cidr-file cidr.txt --threads 100 --ip-txt --iptest --display 30

# 仅保留下载速度 >= 10 MB/s 的 IP
python cf_tri_net_detect.py 162.159.38.0/24 --ip-txt --iptest --min-speed 10
```

### 方式二：启动器（Windows）

```bat
cf_scan.bat                      :: 默认扫描 172.64.229.0/22
cf_scan.bat 162.159.38.0/24 100  :: 指定 CIDR 与线程数
```

### 常用参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `--cidr-file` | — | 从文件读取 CIDR 列表 |
| `--threads` | 50 | 并行线程数（大网段可 100） |
| `--top` | 50 | 对延迟最低的 N 个 IP 做 traceroute（0=禁用） |
| `--ping-count` | 3 | 每 IP ping 次数（大网段建议 2） |
| `--ip-txt` | 关 | 输出 `ip.txt`（格式 `IP 端口`），供优选工具使用 |
| `--iptest` | 关 | 调用 `iptest.exe` 实测下载速度并重整 `iptest_result.txt` |
| `--min-speed` | 0.0 | 仅输出实测速度 ≥ 该值的 IP；**默认 0.0 = 保留所有真实速度** |
| `--csv-only` | 关 | 仅输出 CSV 报告 |

---

## 输出文件

| 文件 | 说明 |
|---|---|
| `cf_report_<cidr>_<时间戳>.csv` | 完整检测报告（含评分分项、回程线路、速度） |
| `cf_top_ips_<cidr>_<时间戳>.txt` | Top 优选 IP 摘要 |
| `ip.txt` | 优选 IP 列表（`IP 端口`，供 CF 优选工具） |
| `iptest_result.txt` | 速度实测结果（标准格式） |
| `iptest_raw_full.csv` | iptest 完整原始数据（含失败行）备份 |

---

## 关于「CFtrace / NextTrace / backtrace」的说明（重要）

本项目**没有嵌入 CFtrace 或 NextTrace 的代码**。澄清如下：

- **CFtrace / NextTrace**：仅借鉴其「CF IP 三网回程检测」的**思路**。本项目 traceroute 使用
  操作系统自带的 `tracert`/`traceroute` 命令（subprocess 调用），路由解析与落地推断均为自研。
- **oneclickvirt/backtrace**：本项目的**线路分类逻辑**（联通 9929/4837、电信 CN2/163、移动
  CMIN2/CMI 的 ASN 顺序/跳数判定）是**逐字移植**（Go→Python 翻译）自 backtrace 的
  `bk/ipv4_asn.go`、`bk/model/model.go`、`bk/route_classification.go`。该部分为
  **Apache License 2.0** 衍生作品，已在 `NOTICE` 中署名并标注修改。
- **oneclickvirt/iptest**：`iptest.exe` 作为**外部二进制**被调用做下载测速，源码不在本仓库。
- **MaxMind GeoLite2**：离线 ASN/国家库，许可证 **CC BY-SA 4.0**。

详见仓库根目录的 `LICENSE` 与 `NOTICE`。

---

## 许可证

- 本项目整体以 **Apache License 2.0** 发布（含对 backtrace 衍生代码的合规署名）。
- 第三方组件许可证见 `NOTICE`。

---

## 免责声明

本工具仅用于网络质量研究与 Cloudflare CDN 优选学习。使用者需自行确保对目标网段的扫描行为
符合当地法律法规与网络使用规范。GeoLite2 数据为 MaxMind 提供，按其许可证使用。
