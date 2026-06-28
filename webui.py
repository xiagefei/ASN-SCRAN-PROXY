#!/usr/bin/env python3
import sys, os, json, time, queue, threading, socket as sock_mod, ssl, urllib.request, struct, ipaddress, platform, uuid, random, re
from pathlib import Path
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file
from flask_socketio import SocketIO, emit

BASE = Path(__file__).parent.resolve()
app = Flask(__name__, template_folder=str(BASE / "templates"))
app.config['SECRET_KEY'] = os.urandom(16).hex()
app.config['SOCKETIO_ASYNC_MODE'] = 'threading'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

scans = {}
current_scan_id = None
scan_lock = threading.Lock()

def detect_hardware():
    cpu, mem_mb = 4, 2048
    try:
        import psutil
        cpu = psutil.cpu_count() or cpu
        mem_mb = psutil.virtual_memory().total // (1024 * 1024)
    except ImportError:
        import ctypes
        cpu = os.cpu_count() or cpu
        try:
            if platform.system() == "Windows":
                k32 = ctypes.windll.kernel32
                buf = ctypes.create_string_buffer(64)
                k32.GlobalMemoryStatusEx(buf)
                mem_mb = struct.unpack_from("I", buf, 8)[0] // (1024*1024)
        except:
            pass
    return cpu, mem_mb

CPU_CORES, RAM_MB = detect_hardware()
MASSCAN_RATE = CPU_CORES * 1000
CF_SCANNER_CONC = max(200, min(CPU_CORES * 100, 500))
API_CONCURRENT = min(CPU_CORES * 16, 32)
API_CHUNK = 2000 if RAM_MB < 1024 else 5000
API_URL = "https://api.090227.xyz/check"

def expand_port_range(text):
    if not text or not text.strip():
        return None
    ports = []
    for part in text.replace("，", ",").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                for p in range(int(a.strip()), int(b.strip()) + 1):
                    if 1 <= p <= 65535:
                        ports.append(p)
            except:
                raise ValueError(f"无效端口范围: {part}")
        else:
            p = int(part)
            if 1 <= p <= 65535:
                ports.append(p)
            else:
                raise ValueError(f"无效端口: {part}")
    return sorted(set(ports)) if ports else None

class ScanRunner:
    def __init__(self, scan_id, asns, do_speed_test, ports=None, known_ips=None, sid=None,
                 mc_enabled=True, ts_enabled=True, mc_sample_count=20, mc_threshold=1000000,
                 masscan_rate=None, cf_concurrency=None, api_concurrent=None, api_chunk=None):
        self.scan_id = scan_id
        self.asns = [a.strip().replace("AS", "").replace("as", "") for a in asns if a.strip()]
        self.do_speed_test = do_speed_test
        self.custom_ports = ports
        self.known_ips = known_ips or []
        self.sid = sid
        self.mc_enabled = mc_enabled
        self.ts_enabled = ts_enabled
        self.mc_sample_count = max(5, min(mc_sample_count, 500))
        self.mc_threshold = max(1000, mc_threshold)
        self.scan_rate = masscan_rate or MASSCAN_RATE
        self.cf_conc = cf_concurrency or CF_SCANNER_CONC
        self.api_conc = api_concurrent or API_CONCURRENT
        self.api_chunk = api_chunk or API_CHUNK
        self.log_queue = queue.Queue()
        self.status = "pending"
        self.progress = 0
        self.result_file = None
        self.cancelled = False
        self.thread = None

    def emit(self, msg, level="info"):
        entry = {"time": datetime.now().strftime("%H:%M:%S"), "msg": msg, "level": level}
        self.log_queue.put(entry)
        step = ""
        m = re.search(r"Step (\d)/6", msg)
        if m:
            step = f"{m.group(1)}/6"
        elif "完成" in msg or "完成!" in msg:
            step = "done"
        elif "取消" in msg:
            step = "cancel"
        elif "失败" in msg or "出错" in msg:
            step = "error"
        socketio.emit("log", {"step": step, "msg": msg, "progress": self.progress}, to=self.sid)

    def set_status(self, s, progress=None):
        self.status = s
        if progress is not None:
            self.progress = progress
        socketio.emit("status", {"status": s, "progress": progress, "file": self.result_file, "asn_tag": "_".join(self.asns)}, to=self.sid)

    def run(self):
        if self.custom_ports:
            self.emit(f"自定义端口: {', '.join(str(p) for p in self.custom_ports)}")
        if self.known_ips:
            self.emit(f"优先扫描 IP: {', '.join(self.known_ips[:10])}{' ...' if len(self.known_ips) > 10 else ''}")
        self.thread = threading.Thread(target=self._run_scan, daemon=True)
        self.thread.start()

    def _run_scan(self):
        global current_scan_id
        try:
            self.set_status("running", 0)
            self.emit(f"硬件: {CPU_CORES}核 {RAM_MB}MB | 平台: {platform.system()}")
            cidrs = self.fetch_prefixes()
            if self.cancelled: return
            self.set_status("running", 15)
            total_ips = self.expand_ips(cidrs)
            if self.cancelled: return
            socketio.emit("ip_file", {"file": "ips.txt", "count": total_ips}, to=self.sid)
            self.set_status("running", 30)
            open_ports = self.python_masscan()
            if self.cancelled: return
            self.set_status("running", 50)
            cf_hits = self.python_cf_scan()
            if self.cancelled: return
            self.set_status("running", 65)
            verified_count = self.api_verify()
            if self.cancelled: return
            self.set_status("running", 80)
            if self.do_speed_test:
                self.speed_test()
                if self.cancelled: return
                self.set_status("running", 95)
            else:
                self.emit("跳过测速")
            self.output_csv()
            self.set_status("completed", 100)
            self.emit("扫描完成!")
        except Exception as e:
            self.emit(f"失败: {e}", "error")
            self.set_status("error")
        finally:
            with scan_lock:
                current_scan_id = None

    def fetch_prefixes(self):
        self.emit("Step 1/6: ASN -> CIDR")
        all_cidrs = []
        for asn in self.asns:
            url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
            try:
                with urllib.request.urlopen(url, timeout=15) as resp:
                    data = json.loads(resp.read())
                    count = 0
                    for p in data["data"]["prefixes"]:
                        if ":" not in p["prefix"]:
                            all_cidrs.append(p["prefix"])
                            count += 1
                    self.emit(f"  AS{asn} -> {count} IPv4 CIDR")
            except Exception as e:
                self.emit(f"  AS{asn} -> 失败: {e}", "warn")
        with open(BASE / "cidrs.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(all_cidrs))
        self.emit(f"共 {len(all_cidrs)} CIDR")
        return all_cidrs

    def expand_ips(self, cidrs):
        self.emit("Step 2/6: CIDR -> IP")
        ip_file = BASE / "ips.txt"
        total = 0
        with open(ip_file, "w", encoding="utf-8") as out:
            for cidr in cidrs:
                cidr = cidr.strip()
                if not cidr:
                    continue
                try:
                    net = ipaddress.IPv4Network(cidr, strict=False)
                    for ip in net.hosts():
                        out.write(str(ip) + "\n")
                        total += 1
                except Exception as e:
                    self.emit(f"  跳过 {cidr}: {e}", "warn")
        self.emit(f"展开 {total:,} IP")
        return total

    def _scan_worker(self, ip, port, timeout=2):
        try:
            s = sock_mod.socket(sock_mod.AF_INET, sock_mod.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            s.close()
            return f"{ip}:{port}"
        except:
            return None

    def _batch_scan(self, targets, max_workers, label="扫描"):
        results, lock = [], threading.Lock()
        done, total = [0], len(targets)
        task_queue = queue.Queue(maxsize=max_workers * 4)

        def consumer():
            while True:
                item = task_queue.get()
                if item is None:
                    task_queue.task_done()
                    break
                ip, p = item
                r = self._scan_worker(ip, p)
                with lock:
                    done[0] += 1
                    if done[0] % max(1, total // 20) == 0:
                        self.emit(f"  扫描 {label}: {done[0]}/{total} ({done[0]/total*100:.0f}%)")
                    if r:
                        results.append(r)
                task_queue.task_done()

        def producer():
            for ip, p in targets:
                task_queue.put((ip, p))
            for _ in range(max_workers):
                task_queue.put(None)

        from concurrent.futures import ThreadPoolExecutor, as_completed
        prod = threading.Thread(target=producer, daemon=True)
        prod.start()
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            fs = [ex.submit(consumer) for _ in range(min(max_workers, len(targets) or 1))]
            for f in as_completed(fs):
                f.result()
        prod.join()
        return results

    def python_masscan(self):
        self.emit("Step 3/6: 端口扫描 (Python TCP Scanner)")
        ip_file = BASE / "ips.txt"
        port_file = BASE / "ports.txt"
        result_file = BASE / "masscan_result.txt"

        if self.custom_ports:
            ports = self.custom_ports
        else:
            ports = []
            with open(port_file, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        ports.append(int(line))

        all_ips = [l.strip() for l in open(ip_file, encoding="utf-8", errors="ignore") if l.strip()]
        total_ips = len(all_ips)
        max_workers = min(CPU_CORES * 200, 2000)

        if self.mc_enabled and total_ips >= self.mc_threshold:
            if self.ts_enabled:
                self.emit(f"  并行算法: Thompson Sampling + Monte Carlo | 阈值 {self.mc_threshold:,} | 每段采样 {self.mc_sample_count} IP")
                import threading
                saved_known = self.known_ips
                self.known_ips = []
                ts_file = BASE / "masscan_ts_tmp.txt"
                mc_file = BASE / "masscan_mc_tmp.txt"
                ts_ret, mc_ret = [None], [None]
                def run_ts():
                    ts_ret[0] = self._masscan_thompson_sampling(all_ips, ports, max_workers, ts_file)
                def run_mc():
                    mc_ret[0] = self._masscan_monte_carlo(all_ips, ports, max_workers, mc_file)
                t1 = threading.Thread(target=run_ts)
                t2 = threading.Thread(target=run_mc)
                t1.start(); t2.start(); t1.join(); t2.join()
                self.known_ips = saved_known
                merged = set()
                for f in [ts_file, mc_file]:
                    if f.exists():
                        with open(f, encoding="utf-8", errors="ignore") as fh:
                            for line in fh:
                                line = line.strip()
                                if line:
                                    merged.add(line)
                for f in [ts_file, mc_file]:
                    f.unlink() if f.exists() else None
                if self.known_ips:
                    known_targets = [(ip.strip(), p) for ip in self.known_ips for p in ports if ip.strip()]
                    if known_targets:
                        self.emit(f"  优先扫描已知 IP: {len(known_targets)} 探测")
                        for r in self._batch_scan(known_targets, max_workers, "已知IP"):
                            merged.add(r)
                open_count = len(merged)
                with open(result_file, "w", encoding="utf-8") as f:
                    for r in sorted(merged):
                        f.write(r + "\n")
                result = open_count
                self.emit(f"开放端口 (TS+MC 合并): {open_count}")
            else:
                self.emit(f"  算法: Monte Carlo | 阈值 {self.mc_threshold:,} | 每段采样 {self.mc_sample_count} IP")
                result = self._masscan_monte_carlo(all_ips, ports, max_workers, result_file)
        else:
            reason = "MC 已关闭" if not self.mc_enabled else f"IP {total_ips:,} < 阈值 {self.mc_threshold:,}"
            self.emit(f"  算法: 全量扫描 ({reason})")
            merged = set(self._masscan_bruteforce_raw(all_ips, ports, max_workers))
            if self.known_ips:
                known_targets = [(ip.strip(), p) for ip in self.known_ips for p in ports if ip.strip()]
                if known_targets:
                    self.emit(f"  优先扫描已知 IP: {len(known_targets)} 探测")
                    for r in self._batch_scan(known_targets, max_workers, "已知IP"):
                        merged.add(r)
            open_count = len(merged)
            with open(result_file, "w", encoding="utf-8") as f:
                for r in sorted(merged):
                    f.write(r + "\n")
            result = open_count
            self.emit(f"开放端口: {open_count}")

        # Notify frontend about masscan result file
        masscan_count = 0
        if result_file.exists():
            masscan_count = sum(1 for _ in open(result_file, encoding="utf-8", errors="ignore") if _.strip())
        socketio.emit("masscan_file", {"raw_file": "masscan_result.txt", "result_file": "masscan_result.txt", "count": masscan_count}, to=self.sid)
        return result

    def _masscan_bruteforce_raw(self, all_ips, ports, max_workers):
        self.emit(f"全量扫描: {len(all_ips)} IP")
        targets = [(ip, p) for ip in all_ips for p in ports]
        return self._batch_scan(targets, max_workers, f"{len(targets)} 任务")

    def _masscan_bruteforce(self, all_ips, ports, max_workers, result_file):
        results = self._masscan_bruteforce_raw(all_ips, ports, max_workers)
        with open(result_file, "w", encoding="utf-8") as f:
            for r in results:
                f.write(r + "\n")
        self.emit(f"开放端口: {len(results)}")
        return len(results)

    def _masscan_monte_carlo(self, all_ips, ports, max_workers, result_file):
        self.emit(f"大规模扫描 ({len(all_ips):,} IP) — Monte Carlo 优化")
        self.emit("  Phase 1/4: 随机勘探")
        random.seed(42)

        subnets = {}
        for ip_str in all_ips:
            parts = ip_str.split(".")
            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}"
            subnets.setdefault(subnet, []).append(ip_str)
        subnet_list = sorted(subnets.items())
        total_subnets = len(subnet_list)
        self.emit(f"  共 {total_subnets} 个 /24 段, {len(all_ips):,} IP")

        MC_SAMPLE_PER_SUBNET = self.mc_sample_count
        MC_MAX_SAMPLES = 50000
        sample_targets = []
        for subnet, ips in subnet_list:
            n = min(MC_SAMPLE_PER_SUBNET, len(ips))
            for ip in random.sample(ips, n):
                for p in ports:
                    sample_targets.append((ip, p))
        if len(sample_targets) > MC_MAX_SAMPLES:
            sample_targets = random.sample(sample_targets, MC_MAX_SAMPLES)

        self.emit(f"  Phase 1 样本: {len(sample_targets)} 探测")
        sample_results = self._batch_scan(sample_targets, max_workers, "勘探")

        open_set = set()
        for r in sample_results:
            open_set.add(r.split(":")[0])
        density_map = {}
        for ip_str in open_set:
            subnet = ".".join(ip_str.split(".")[:3])
            density_map[subnet] = density_map.get(subnet, 0) + 1

        scored = []
        for subnet, ips in subnet_list:
            hits = density_map.get(subnet, 0)
            sampled = min(MC_SAMPLE_PER_SUBNET, len(ips))
            scored.append((hits / sampled if sampled > 0 else 0, subnet, ips))
        scored.sort(key=lambda x: -x[0])
        high_density = [s for s in scored if s[0] > 0]
        self.emit(f"  Phase 2/4: {len(high_density)} 个含开放端口的 /24 段")
        if high_density:
            for subnet, pct in [(s[1], f"{s[0]*100:.1f}%") for s in high_density[:5]]:
                self.emit(f"    {subnet}.0/24  密度={pct}")

        max_probes = min(200000, len(all_ips) * len(ports) // 2)
        focus_targets = []
        ip_budget = max(0, max_probes - len(sample_targets)) // len(ports)

        if ip_budget > 0 and high_density:
            self.emit(f"  Phase 3/4: 聚焦扫描 — 预算 {ip_budget} IP")
            max_density = max(s[0] for s in high_density)
            for density, subnet, ips in scored:
                if ip_budget <= 0:
                    break
                if density == 0:
                    continue
                already = set()
                for sr in sample_results:
                    parts = sr.split(":")
                    if parts[0].startswith(subnet + "."):
                        already.add(parts[0])
                remaining = [ip for ip in ips if ip not in already]
                if not remaining:
                    continue
                alloc = max(20, min(int(ip_budget * density / max_density), len(remaining), ip_budget))
                for ip in random.sample(remaining, alloc):
                    for p in ports:
                        focus_targets.append((ip, p))
                ip_budget -= alloc

        self.emit(f"  Phase 3 聚焦: {len(focus_targets)} 探测")
        focus_results = self._batch_scan(focus_targets, max_workers, "聚焦")

        scanned_ips = set()
        for r in sample_results + focus_results:
            scanned_ips.add(r.split(":")[0])
        scanned_subnets = set(".".join(ip.split(".")[:3]) for ip in scanned_ips)

        residual_targets = []
        for subnet, ips in subnet_list:
            if subnet in scanned_subnets:
                continue
            for ip in random.sample(ips, min(5, len(ips))):
                for p in ports:
                    residual_targets.append((ip, p))

        if residual_targets:
            self.emit(f"  Phase 4/4: 残差扫描 — {len(residual_targets)} 探测 (覆盖未触及段)")
            residual_results = self._batch_scan(residual_targets, max_workers, "残差")
            results_map = {}
            for r in sample_results + focus_results + residual_results:
                results_map[r] = True
            all_results = list(results_map.keys())
        else:
            all_results = list(set(sample_results + focus_results))

        if self.known_ips:
            known_targets = [(ip.strip(), p) for ip in self.known_ips for p in ports if ip.strip()]
            if known_targets:
                self.emit(f"  优先扫描已知 IP: {len(known_targets)} 探测")
                known_results = self._batch_scan(known_targets, max_workers, "已知IP")
                results_map = {}
                for r in all_results + known_results:
                    results_map[r] = True
                all_results = list(results_map.keys())

        open_count = len(all_results)
        with open(result_file, "w", encoding="utf-8") as f:
            for r in all_results:
                f.write(r + "\n")

        total_scanned = len(sample_targets) + len(focus_targets) + len(residual_targets)
        total_possible = len(all_ips) * len(ports)
        pct = (1 - total_scanned / total_possible) * 100 if total_possible else 0
        self.emit(f"开放端口: {open_count} | 扫描量: {total_scanned:,}/{total_possible:,} ({pct:.0f}% 节省)")
        covered = len(scanned_subnets) + (len(residual_targets) // (len(ports) * 5) if residual_targets else 0)
        self.emit(f"  覆盖 /24 段: {min(covered, total_subnets)}/{total_subnets}")
        return open_count

    def _masscan_thompson_sampling(self, all_ips, ports, max_workers, result_file):
        self.emit(f"大规模扫描 ({len(all_ips):,} IP) — Thompson Sampling 优化")
        import random
        random.seed(42)

        subnets = {}
        for ip_str in all_ips:
            parts = ip_str.split(".")
            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}"
            subnets.setdefault(subnet, []).append(ip_str)
        subnet_list = sorted(subnets.items())
        total_subnets = len(subnet_list)
        self.emit(f"  共 {total_subnets} 个 /24 段")

        # Beta posterior per subnet: Beta(alpha, beta)
        alpha = {s: 1 for s, _ in subnet_list}
        beta = {s: 1 for s, _ in subnet_list}
        scanned = {s: set() for s, _ in subnet_list}

        BATCH_SIZE = min(self.mc_sample_count * 5, 200)
        max_ips_to_scan = min(200000, len(all_ips))
        rounds = (max_ips_to_scan + BATCH_SIZE - 1) // BATCH_SIZE
        self.emit(f"  预算: {max_ips_to_scan} IP | 批大小: {BATCH_SIZE} | 轮次: {rounds}")
        all_results = []
        pulled_count = {s: 0 for s, _ in subnet_list}

        for rnd in range(rounds):
            if self.cancelled:
                break

            chosen = []
            for _ in range(BATCH_SIZE):
                best_subnet, best_score = None, -1
                for subnet, ips in subnet_list:
                    if len(scanned[subnet]) >= len(ips):
                        continue
                    score = random.betavariate(alpha[subnet], beta[subnet])
                    if score > best_score:
                        best_score = score
                        best_subnet = subnet
                if best_subnet is None:
                    break
                available = [ip for ip in subnets[best_subnet] if ip not in scanned[best_subnet]]
                if not available:
                    continue
                ip = random.choice(available)
                scanned[best_subnet].add(ip)
                chosen.append((best_subnet, ip))
                pulled_count[best_subnet] += 1

            if not chosen:
                break

            targets = [(ip, p) for _, ip in chosen for p in ports]
            batch_results = self._batch_scan(targets, max_workers, f"TS {rnd+1}/{rounds}")

            found_map = {}
            for r in batch_results:
                all_results.append(r)
                sip = r.split(":")[0]
                found_map[sip] = True

            for subnet, ip in chosen:
                if found_map.get(ip):
                    alpha[subnet] += 1
                else:
                    beta[subnet] += 1

            if (rnd + 1) % max(1, rounds // 10) == 0:
                total_pulled = sum(pulled_count.values())
                top3 = sorted(((pulled_count[s], s) for s, _ in subnet_list), reverse=True)[:3]
                top_info = " | ".join(f"{s}.0/24({n})" for n, s in top3 if n > 0)
                self.emit(f"  轮次 {rnd+1}/{rounds} | 已扫 {total_pulled} IP | 发现 {len(set(all_results))} 端口 | 热门: {top_info}")

        all_results = list(set(all_results))
        open_count = len(all_results)

        if self.known_ips:
            known_targets = [(ip.strip(), p) for ip in self.known_ips for p in ports if ip.strip()]
            if known_targets:
                self.emit(f"  优先扫描已知 IP: {len(known_targets)} 探测")
                known_results = self._batch_scan(known_targets, max_workers, "已知IP")
                results_map = {}
                for r in all_results + known_results:
                    results_map[r] = True
                all_results = list(results_map.keys())
                open_count = len(all_results)

        with open(result_file, "w", encoding="utf-8") as f:
            for r in all_results:
                f.write(r + "\n")

        total_scanned = sum(pulled_count.values()) * len(ports)
        total_possible = len(all_ips) * len(ports)
        pct = (1 - total_scanned / total_possible) * 100 if total_possible else 0
        active_subnets = sum(1 for s, _ in subnet_list if pulled_count[s] > 0)
        self.emit(f"开放端口: {open_count} | 扫描量: {total_scanned:,}/{total_possible:,} ({pct:.0f}% 节省)")
        self.emit(f"  覆盖 /24 段: {active_subnets}/{total_subnets} | 算法: Thompson Sampling")
        return open_count

    def python_cf_scan(self):
        self.emit("Step 4/6: Cloudflare 检测")
        input_file = BASE / "masscan_result.txt"
        output_file = BASE / "cf_hits.txt"
        if not input_file.exists() or input_file.stat().st_size == 0:
            self.emit("无开放端口，跳过")
            return 0
        targets = [l.strip() for l in open(input_file, encoding="utf-8", errors="ignore") if l.strip()]
        self.emit(f"检测 {len(targets)} 个目标 (并发: {self.cf_conc})")
        hits, lock = [], threading.Lock()
        checked = [0]

        def check_cf(target):
            ip_port = target
            is_hit = False
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
                parts = target.split(":")
                ip, port = parts[0], int(parts[1]) if len(parts) > 1 else 443
                s = sock_mod.socket(sock_mod.AF_INET, sock_mod.SOCK_STREAM)
                s.settimeout(3)
                s.connect((ip, port))
                ssock = ctx.wrap_socket(s, server_hostname="cloudflare.com")
                ssock.settimeout(5)
                req = f"GET / HTTP/1.1\r\nHost: www.cloudflare.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode()
                ssock.sendall(req)
                resp = b""
                while True:
                    try:
                        chunk = ssock.recv(4096)
                        if not chunk:
                            break
                        resp += chunk
                    except:
                        break
                ssock.close()
                resp_str = resp.decode("utf-8", errors="replace")
                if "cloudflare" in resp_str.lower() or "CF-RAY" in resp_str:
                    with lock:
                        hits.append(f"{ip_port}  status=200 server=cloudflare")
                    is_hit = True
            except:
                pass
            with lock:
                checked[0] += 1
                if checked[0] % 100 == 0:
                    self.emit(f"  CF检测: {checked[0]}/{len(targets)} hits={len(hits)}")
            return is_hit

        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=self.cf_conc) as ex:
            for f in as_completed({ex.submit(check_cf, t): t for t in targets}):
                pass
        with open(output_file, "w", encoding="utf-8") as f:
            for h in hits:
                f.write(h + "\n")
        self.emit(f"CF 节点: {len(hits)}")
        return len(hits)

    def api_verify(self):
        self.emit("Step 5/6: API 精筛")
        from verify import main as verify_main
        import io, sys as sys_mod
        hits_file = BASE / "cf_hits.txt"
        verified_file = BASE / "verified.txt"
        if not hits_file.exists() or hits_file.stat().st_size == 0:
            self.emit("无 CF 节点，跳过")
            return 0
        old_args, old_stdout = sys_mod.argv, sys_mod.stdout
        try:
            cap = io.StringIO()
            sys_mod.stdout = cap
            sys_mod.argv = ["verify.py", "--input", str(hits_file), "--output", str(verified_file), "--api", API_URL, "--chunk", str(self.api_chunk), "--concurrent", str(self.api_conc)]
            verify_main()
            sys_mod.stdout = old_stdout
            for line in cap.getvalue().split("\n"):
                if line.strip():
                    self.emit(f"  {line.strip()}")
        except Exception as e:
            sys_mod.stdout = old_stdout
            self.emit(f"  API验证出错: {e}", "error")
            raise
        finally:
            sys_mod.argv = old_args
        passed = sum(1 for _ in open(verified_file, encoding="utf-8", errors="ignore")) if verified_file.exists() else 0
        self.emit(f"精筛通过: {passed}")
        return passed

    def speed_test(self):
        self.emit("Step 6/6: 测速")
        verified_file = BASE / "verified.txt"
        if not verified_file.exists() or verified_file.stat().st_size == 0:
            self.emit("无节点，跳过")
            return
        lines = [l.strip() for l in open(verified_file, encoding="utf-8", errors="ignore") if l.strip() and not l.startswith("#")]
        if len(lines) <= 1:
            self.emit("无节点，跳过")
            return
        header, entries = lines[0], lines[1:]
        total = len(entries)
        self.emit(f"节点数: {total}")
        with open(verified_file, "w", encoding="utf-8") as f:
            f.write(header + "\n")
            for i, entry in enumerate(entries):
                parts = entry.split(",")
                if len(parts) < 9:
                    continue
                ip, port = parts[0], parts[1]
                latency = 0
                try:
                    s = sock_mod.socket(sock_mod.AF_INET, sock_mod.SOCK_STREAM)
                    s.settimeout(5)
                    t0 = time.time()
                    s.connect((ip, int(port)))
                    latency = round((time.time() - t0) * 1000)
                    s.close()
                except:
                    pass
                speed_mbps = 0
                if latency > 0:
                    try:
                        s = sock_mod.socket(sock_mod.AF_INET, sock_mod.SOCK_STREAM)
                        s.settimeout(5)
                        s.connect((ip, int(port)))
                        ssock = ssl.wrap_socket(s, server_hostname="speed.cloudflare.com")
                        ssock.settimeout(20)
                        req = f"GET /__down?bytes=10485760 HTTP/1.1\r\nHost: speed.cloudflare.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode()
                        t0 = time.time()
                        ssock.sendall(req)
                        downloaded = 0
                        while True:
                            try:
                                chunk = ssock.recv(65536)
                                if not chunk:
                                    break
                                downloaded += len(chunk)
                            except:
                                break
                        elapsed = time.time() - t0
                        if elapsed > 0.5:
                            speed_mbps = round(downloaded * 8 / elapsed / 1000000, 2)
                        ssock.close()
                    except:
                        pass
                parts[6] = str(latency)
                parts[7] = str(speed_mbps)
                f.write(",".join(parts) + "\n")
                if (i + 1) % 10 == 0 or (i + 1) == total:
                    self.emit(f"  测速: {i+1}/{total} | 延迟 {latency}ms 速度 {speed_mbps}Mbps")
        self.emit(f"测速完成: {total} 节点")
    def output_csv(self):
        verified_file = BASE / "verified.txt"
        if not verified_file.exists() or verified_file.stat().st_size == 0:
            self.emit("无结果")
            return

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        asn_tag = "_".join(self.asns)
        output = BASE / f"output_{asn_tag}_{ts}.csv"
        lines = []
        with open(verified_file, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("IP地址"):
                    continue
                if line.count(",") < 8:
                    continue
                lines.append(line)
        with open(output, "w", encoding="utf-8") as f:
            for line in lines:
                f.write(line + "\n")
        self.emit(f"可用节点: {len(lines)} 条 -> {output.name}")
        self.result_file = output.name

# ── Routes ──

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/status")
def api_status():
    return jsonify({
        "cpu": CPU_CORES,
        "ram": RAM_MB,
        "default_config": {
            "masscan_rate": MASSCAN_RATE,
            "cf_concurrency": CF_SCANNER_CONC,
            "api_concurrent": API_CONCURRENT,
            "api_chunk": API_CHUNK,
            "ports": "443,8443,2053,2083,2087,2096"
        },
        "running": current_scan_id is not None
    })

@app.route("/api/results")
def api_results():
    items = []
    result_file = BASE / "verified.txt"
    if result_file.exists() and result_file.stat().st_size > 0:
        with open(result_file, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("IP地址"):
                    continue
                parts = line.split(",")
                if len(parts) >= 9:
                    items.append({
                        "ip": parts[0], "port": parts[1], "tls": parts[2],
                        "colo": parts[3], "country": parts[4], "region": parts[5],
                        "latency": parts[6], "speed": parts[7], "asn": parts[8]
                    })
    return jsonify(items)

@app.route("/api/results/latest")
def api_results_latest():
    files = sorted(BASE.glob("output_*.csv"), reverse=True)
    if files:
        return jsonify({"filename": files[0].name})
    return jsonify({"filename": None})

@app.route("/api/cancel", methods=["POST"])
def api_cancel():
    global current_scan_id
    with scan_lock:
        sid = current_scan_id
        if sid and sid in scans:
            scans[sid].cancelled = True
            scans[sid].set_status("cancelled")
            current_scan_id = None
            return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "no running scan"})

@app.route("/api/download/<path:filename>")
def api_download(filename):
    file_path = BASE / filename
    if not file_path.exists():
        return "File not found", 404
    return send_file(str(file_path), as_attachment=True)

# ── Socket.IO Events ──

@socketio.on("connect")
def on_connect():
    pass

@socketio.on("start_scan")
def on_start_scan(data):
    global current_scan_id
    if not data:
        socketio.emit("status", {"status": "error", "msg": "无效参数"}, to=request.sid)
        return
    asns = data.get("asns", "")
    if not asns:
        socketio.emit("status", {"status": "error", "msg": "ASN 编号不能为空"}, to=request.sid)
        return

    with scan_lock:
        if current_scan_id:
            socketio.emit("status", {"status": "busy", "msg": "已有任务运行中"}, to=request.sid)
            return

    asn_list = [a.strip().replace("AS", "").replace("as", "") for a in asns.replace("，", ",").split(",") if a.strip()]
    if not asn_list:
        socketio.emit("status", {"status": "error", "msg": "无效 ASN 编号"}, to=request.sid)
        return

    raw_ports = data.get("ports", "")
    port_list = None
    if raw_ports:
        try:
            port_list = expand_port_range(raw_ports)
            if port_list is None:
                socketio.emit("status", {"status": "error", "msg": "无效端口"}, to=request.sid)
                return
        except (ValueError, Exception) as e:
            socketio.emit("status", {"status": "error", "msg": f"端口格式错误: {e}"}, to=request.sid)
            return

    raw_known = data.get("known_ips", "")
    known_list = []
    if raw_known:
        known_list = [ip.strip() for ip in raw_known.replace("，", ",").split(",") if ip.strip()]

    mc_enabled = data.get("mc_enabled", True)
    if isinstance(mc_enabled, str):
        mc_enabled = mc_enabled.lower() in ("true", "1", "yes")
    ts_enabled = data.get("ts_enabled", True)
    if isinstance(ts_enabled, str):
        ts_enabled = ts_enabled.lower() in ("true", "1", "yes")
    mc_sample = int(data.get("mc_sample", 20))
    mc_threshold = int(data.get("mc_threshold", 1000000))
    speed_test = data.get("speed_test", True)
    if isinstance(speed_test, str):
        speed_test = speed_test.lower() in ("true", "1", "yes")
    masscan_rate = data.get("masscan_rate")
    cf_concurrency = data.get("cf_concurrency")
    api_concurrent = data.get("api_concurrent")
    api_chunk = data.get("api_chunk")

    scan_id = uuid.uuid4().hex[:12]
    runner = ScanRunner(scan_id, asn_list, speed_test, ports=port_list, known_ips=known_list, sid=request.sid, mc_enabled=mc_enabled, ts_enabled=ts_enabled, mc_sample_count=mc_sample, mc_threshold=mc_threshold, masscan_rate=masscan_rate, cf_concurrency=cf_concurrency, api_concurrent=api_concurrent, api_chunk=api_chunk)
    with scan_lock:
        scans[scan_id] = runner
        current_scan_id = scan_id
    runner.run()
    socketio.emit("status", {"status": "running", "scan_id": scan_id}, to=request.sid)

if __name__ == "__main__":
    print(f"  ASN IP Scanner Web UI")
    print(f"  Open browser: http://127.0.0.1:5000")
    socketio.run(app, host="0.0.0.0", port=5000, allow_unsafe_werkzeug=True)
