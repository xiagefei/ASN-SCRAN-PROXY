#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloudflare CDN IP 三网检测脚本 (CF Tri-Net Detection)
=====================================================

功能模块：
  1. 快速 ICMP RTT 检测 — 并行 Ping 整个网段
  2. 路由落地判断 — 通过 Cloudflare /cdn-cgi/trace 获取 colo 代码，映射到城市/国家
  3. 多端口 TCP RTT — 测试多个端口的 TCP 连接延迟，判断是否走优质线路
  4. 三网评估 — 基于落地数据中心和 RTT 评估联通/电信/移动三网适配性
  5. 优质线路判断 — 综合 RTT、TCP 延迟、落地位置进行评级
  6. Cloudflare 优选推荐 — 筛选适合做 CDN 优选的 IP
  7. 稀有优质段识别 — 识别稀有优质 IP 段

用法：
  python cf_tri_net_detect.py [CIDR] [options]

示例：
  python cf_tri_net_detect.py 172.64.229.0/22
  python cf_tri_net_detect.py 172.64.229.0/22 --top 30 --output report.json
  python cf_tri_net_detect.py 172.64.229.0/22 --ports 80,443,2052,2083 --threads 100
  python cf_tri_net_detect.py 172.64.229.0/22 --sample 50  # 抽样测试
"""

__version__ = '1.0.0'

import os
import sys
import re
import io
import time
import json
import math
import socket
import ssl
import argparse
import platform
import subprocess
import ipaddress
import statistics
import urllib.request
import urllib.error
from datetime import datetime
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# ============================================================
# GeoLite2 ASN/Country 集成 (基于 maxminddb)
# ============================================================

try:
    import maxminddb
    _HAS_MAXMIND = True
except ImportError:
    _HAS_MAXMIND = False

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_ASN_DB_PATH = os.path.join(_SCRIPT_DIR, 'GeoLite2-ASN.mmdb')
_COUNTRY_DB_PATH = os.path.join(_SCRIPT_DIR, 'GeoLite2-Country.mmdb')


class GeoIPReader:
    """GeoLite2 ASN/Country 离线查询 (线程安全, 全局复用)"""

    _instance = None

    def __init__(self):
        self.asn_reader = None
        self.country_reader = None
        if _HAS_MAXMIND:
            try:
                # Windows 中文路径 workaround: maxminddb 不支持非 ASCII 路径,
                # 切换到脚本目录后用相对路径打开
                old_cwd = os.getcwd()
                os.chdir(_SCRIPT_DIR)
                try:
                    if os.path.exists('GeoLite2-ASN.mmdb'):
                        self.asn_reader = maxminddb.open_database('GeoLite2-ASN.mmdb')
                    if os.path.exists('GeoLite2-Country.mmdb'):
                        self.country_reader = maxminddb.open_database('GeoLite2-Country.mmdb')
                finally:
                    os.chdir(old_cwd)
            except Exception:
                pass

    @classmethod
    def get(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def lookup_asn(self, ip_str):
        """查询 IP 的 ASN 号和组织名. 返回 (asn_number, asn_org) 或 (None, None)"""
        if not self.asn_reader:
            return None, None
        try:
            record = self.asn_reader.get(ip_str)
            if record and isinstance(record, dict):
                return record.get('autonomous_system_number'), \
                       record.get('autonomous_system_organization', '')
        except Exception:
            pass
        return None, None

    def lookup_country(self, ip_str):
        """查询 IP 的国家代码. 返回 'CN'/'US'/... 或 None"""
        if not self.country_reader:
            return None
        try:
            record = self.country_reader.get(ip_str)
            if record and isinstance(record, dict):
                country = record.get('country')
                if country and isinstance(country, dict):
                    return country.get('iso_code')
        except Exception:
            pass
        return None

    def close(self):
        if self.asn_reader:
            try: self.asn_reader.close()
            except: pass
        if self.country_reader:
            try: self.country_reader.close()
            except: pass

# ============================================================
# 常量定义
# ============================================================

# Cloudflare 常用代理端口
CF_PORTS_DEFAULT = [80, 443, 2052, 2083, 2086, 2087, 2095, 2096]

# OS 检测
IS_WINDOWS = platform.system() == 'Windows'
IS_LINUX = platform.system() == 'Linux'
IS_MACOS = platform.system() == 'Darwin'

# Cloudflare 数据中心代码 -> 城市/国家映射
CF_COLO_MAP = {
    # 亚洲
    'HKG': ('Hong Kong',       'HK', '中国香港'),
    'NRT': ('Tokyo',           'JP', '日本东京'),
    'KIX': ('Osaka',           'JP', '日本大阪'),
    'SIN': ('Singapore',       'SG', '新加坡'),
    'ICN': ('Seoul',           'KR', '韩国首尔'),
    'TPE': ('Taipei',          'TW', '中国台北'),
    'BKK': ('Bangkok',         'TH', '泰国曼谷'),
    'KUL': ('Kuala Lumpur',    'MY', '马来西亚吉隆坡'),
    'CGK': ('Jakarta',         'ID', '印尼雅加达'),
    'MNL': ('Manila',          'PH', '菲律宾马尼拉'),
    'MUM': ('Mumbai',          'IN', '印度孟买'),
    'MAA': ('Chennai',         'IN', '印度金奈'),
    'DEL': ('Delhi',           'IN', '印度德里'),
    'BOM': ('Mumbai',          'IN', '印度孟买'),
    'DXB': ('Dubai',           'AE', '迪拜'),
    'ISB': ('Islamabad',       'PK', '巴基斯坦伊斯兰堡'),
    'KHI': ('Karachi',         'PK', '巴基斯坦卡拉奇'),
    'CMB': ('Colombo',         'LK', '斯里兰卡科伦坡'),
    'DAC': ('Dhaka',           'BD', '孟加拉达卡'),
    'HAN': ('Hanoi',           'VN', '越南河内'),
    'SGN': ('Ho Chi Minh',     'VN', '越南胡志明'),
    'PNH': ('Phnom Penh',      'KH', '柬埔寨金边'),
    'VTE': ('Vientiane',       'LA', '老挝万象'),
    'RGN': ('Yangon',           'MM', '缅甸仰光'),
    # 北美
    'LAX': ('Los Angeles',     'US', '美国洛杉矶'),
    'SJC': ('San Jose',        'US', '美国圣何塞'),
    'SFO': ('San Francisco',   'US', '美国旧金山'),
    'SEA': ('Seattle',         'US', '美国西雅图'),
    'PDX': ('Portland',        'US', '美国波特兰'),
    'PHX': ('Phoenix',         'US', '美国凤凰城'),
    'DEN': ('Denver',          'US', '美国丹佛'),
    'DFW': ('Dallas',          'US', '美国达拉斯'),
    'ORD': ('Chicago',         'US', '美国芝加哥'),
    'ATL': ('Atlanta',         'US', '美国亚特兰大'),
    'MIA': ('Miami',           'US', '美国迈阿密'),
    'IAD': ('Washington',      'US', '美国华盛顿'),
    'EWR': ('Newark',          'US', '美国纽瓦克'),
    'JFK': ('New York',        'US', '美国纽约'),
    'BOS': ('Boston',          'US', '美国波士顿'),
    'MSP': ('Minneapolis',     'US', '美国明尼阿波利斯'),
    'SLC': ('Salt Lake City',  'US', '美国盐湖城'),
    'LAS': ('Las Vegas',       'US', '美国拉斯维加斯'),
    'SAN': ('San Diego',       'US', '美国圣地亚哥'),
    'HNL': ('Honolulu',        'US', '美国夏威夷'),
    'YYZ': ('Toronto',         'CA', '加拿大多伦多'),
    'YVR': ('Vancouver',       'CA', '加拿大温哥华'),
    'YUL': ('Montreal',        'CA', '加拿大蒙特利尔'),
    'MEX': ('Mexico City',     'MX', '墨西哥墨西哥城'),
    'GDL': ('Guadalajara',     'MX', '墨西哥瓜达拉哈拉'),
    # 欧洲
    'LHR': ('London',          'GB', '英国伦敦'),
    'MAN': ('Manchester',      'GB', '英国曼彻斯特'),
    'EDI': ('Edinburgh',       'GB', '英国爱丁堡'),
    'CDG': ('Paris',           'FR', '法国巴黎'),
    'MRS': ('Marseille',       'FR', '法国马赛'),
    'FRA': ('Frankfurt',       'DE', '德国法兰克福'),
    'MUC': ('Munich',          'DE', '德国慕尼黑'),
    'HAM': ('Hamburg',         'DE', '德国汉堡'),
    'AMS': ('Amsterdam',       'NL', '荷兰阿姆斯特丹'),
    'ARN': ('Stockholm',       'SE', '瑞典斯德哥尔摩'),
    'OSL': ('Oslo',            'NO', '挪威奥斯陆'),
    'CPH': ('Copenhagen',      'DK', '丹麦哥本哈根'),
    'HEL': ('Helsinki',        'FI', '芬兰赫尔辛基'),
    'VIE': ('Vienna',          'AT', '奥地利维也纳'),
    'WAW': ('Warsaw',          'PL', '波兰华沙'),
    'PRG': ('Prague',          'CZ', '捷克布拉格'),
    'BUD': ('Budapest',        'HU', '匈牙利布达佩斯'),
    'MAD': ('Madrid',          'ES', '西班牙马德里'),
    'BCN': ('Barcelona',       'ES', '西班牙巴塞罗那'),
    'LIS': ('Lisbon',          'PT', '葡萄牙里斯本'),
    'MXP': ('Milan',           'IT', '意大利米兰'),
    'FCO': ('Rome',            'IT', '意大利罗马'),
    'ATH': ('Athens',          'GR', '希腊雅典'),
    'IST': ('Istanbul',        'TR', '土耳其伊斯坦布尔'),
    'DME': ('Moscow',          'RU', '俄罗斯莫斯科'),
    'SVO': ('Moscow',          'RU', '俄罗斯莫斯科'),
    'KBP': ('Kyiv',            'UA', '乌克兰基辅'),
    'OTP': ('Bucharest',       'RO', '罗马尼亚布加勒斯特'),
    'SOF': ('Sofia',           'BG', '保加利亚索菲亚'),
    'BEG': ('Belgrade',        'RS', '塞尔维亚贝尔格莱德'),
    'ZAG': ('Zagreb',          'HR', '克罗地亚萨格勒布'),
    'LUX': ('Luxembourg',      'LU', '卢森堡'),
    'BRU': ('Brussels',        'BE', '比利时布鲁塞尔'),
    'DUB': ('Dublin',          'IE', '爱尔兰都柏林'),
    'ZRH': ('Zurich',          'CH', '瑞士苏黎世'),
    'GVA': ('Geneva',          'CH', '瑞士日内瓦'),
    # 南美
    'GRU': ('Sao Paulo',       'BR', '巴西圣保罗'),
    'GIG': ('Rio de Janeiro',  'BR', '巴西里约热内卢'),
    'EZE': ('Buenos Aires',    'AR', '阿根廷布宜诺斯艾利斯'),
    'SCL': ('Santiago',        'CL', '智利圣地亚哥'),
    'BOG': ('Bogota',          'CO', '哥伦比亚波哥大'),
    'LIM': ('Lima',            'PE', '秘鲁利马'),
    # 大洋洲
    'SYD': ('Sydney',          'AU', '澳大利亚悉尼'),
    'MEL': ('Melbourne',       'AU', '澳大利亚墨尔本'),
    'BNE': ('Brisbane',        'AU', '澳大利亚布里斯班'),
    'PER': ('Perth',           'AU', '澳大利亚珀斯'),
    'AKL': ('Auckland',        'NZ', '新西兰奥克兰'),
    # 非洲
    'JNB': ('Johannesburg',    'ZA', '南非约翰内斯堡'),
    'CPT': ('Cape Town',       'ZA', '南非开普敦'),
    'NBO': ('Nairobi',         'KE', '肯尼亚内罗毕'),
    'LOS': ('Lagos',           'NG', '尼日利亚拉各斯'),
    'CAI': ('Cairo',           'EG', '埃及开罗'),
    'CMN': ('Casablanca',      'MA', '摩洛哥卡萨布兰卡'),
    'ACC': ('Accra',           'GH', '加纳阿克拉'),
    'DAR': ('Dar es Salaam',   'TZ', '坦桑尼亚达累斯萨拉姆'),
    'ADD': ('Addis Ababa',     'ET', '埃塞俄比亚亚的斯亚贝巴'),
}

# 三网基础评分矩阵 (基于落地数据中心)
# 分数 0-100，越高越好
THREE_NET_BASE_SCORES = {
    'HKG': {'unicom': 92, 'telecom': 88, 'mobile': 95},   # 香港 — 三网均优
    'NRT': {'unicom': 85, 'telecom': 90, 'mobile': 78},   # 东京 — 电信联通优
    'KIX': {'unicom': 82, 'telecom': 87, 'mobile': 75},   # 大阪 — 电信联通优
    'SIN': {'unicom': 72, 'telecom': 80, 'mobile': 90},   # 新加坡 — 移动电信优
    'TPE': {'unicom': 78, 'telecom': 72, 'mobile': 68},   # 台北 — 联通优
    'ICN': {'unicom': 72, 'telecom': 78, 'mobile': 82},   # 首尔 — 移动电信优
    'LAX': {'unicom': 65, 'telecom': 70, 'mobile': 55},   # 洛杉矶 — 电信联通中
    'SJC': {'unicom': 60, 'telecom': 65, 'mobile': 50},   # 圣何塞
    'SFO': {'unicom': 60, 'telecom': 65, 'mobile': 50},   # 旧金山
    'SEA': {'unicom': 55, 'telecom': 60, 'mobile': 45},   # 西雅图
    'ORD': {'unicom': 50, 'telecom': 55, 'mobile': 40},   # 芝加哥
    'IAD': {'unicom': 48, 'telecom': 52, 'mobile': 38},   # 华盛顿
    'EWR': {'unicom': 48, 'telecom': 52, 'mobile': 38},   # 纽瓦克
    'LHR': {'unicom': 45, 'telecom': 50, 'mobile': 35},   # 伦敦
    'FRA': {'unicom': 50, 'telecom': 55, 'mobile': 40},   # 法兰克福
    'AMS': {'unicom': 48, 'telecom': 52, 'mobile': 38},   # 阿姆斯特丹
    'SYD': {'unicom': 40, 'telecom': 45, 'mobile': 50},   # 悉尼
    'GRU': {'unicom': 25, 'telecom': 25, 'mobile': 25},   # 圣保罗
    'JNB': {'unicom': 25, 'telecom': 25, 'mobile': 25},   # 约翰内斯堡
}

# RTT 评级阈值 (毫秒)
RTT_PREMIUM    = 80     # 优质
RTT_GOOD       = 130    # 良好
RTT_NORMAL     = 200    # 普通
RTT_POOR       = 300    # 较差

# TCP RTT 与 ICMP RTT 比值阈值 (用于判断线路质量)
TCP_ICMP_RATIO_GOOD = 1.3    # TCP RTT 不超过 ICMP RTT 的 1.3 倍 -> 优质
TCP_ICMP_RATIO_OK   = 2.0    # 不超过 2.0 -> 普通
# 超过 2.0 -> 较差


# ============================================================
# 控制台颜色 (ANSI)
# ============================================================

class C:
    """ANSI 颜色代码"""
    if IS_WINDOWS:
        os.system('')  # 启用 Windows 10+ ANSI 支持

    RESET   = '\033[0m'
    BOLD    = '\033[1m'
    DIM     = '\033[2m'
    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN    = '\033[96m'
    WHITE   = '\033[97m'
    BG_RED    = '\033[41m'
    BG_GREEN  = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE   = '\033[44m'


# ============================================================
# 工具函数
# ============================================================

def now_str():
    """当前时间字符串"""
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def timestamp_str():
    """用于文件名的时间戳"""
    return datetime.now().strftime('%Y%m%d_%H%M%S')


def sanitize_cidr(cidr):
    """将 CIDR 转换为文件名安全字符串"""
    return cidr.replace('/', '_').replace('.', '-')


def load_cidr_file(path):
    """
    从文件中读取 CIDR 列表 (一行一个)

    规则:
      - 空行忽略
      - 以 # 开头的行视为注释, 忽略
      - 每行可写 CIDR (如 172.64.229.0/22) 或单个 IP (自动当作 /32)

    返回去重后的 CIDR 字符串列表
    """
    cidrs = []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # 允许 IP:PORT / CIDR 等写法, 仅取第一段
                cidr = line.split()[0].split(',')[0].strip()
                if not cidr:
                    continue
                cidrs.append(cidr)
    except FileNotFoundError:
        print(f'{C.RED}错误: 找不到 CIDR 文件: {path}{C.RESET}')
        sys.exit(1)
    except Exception as e:
        print(f'{C.RED}读取 CIDR 文件失败: {path} ({e}){C.RESET}')
        sys.exit(1)

    # 去重并保持顺序
    seen = set()
    uniq = []
    for c in cidrs:
        if c not in seen:
            seen.add(c)
            uniq.append(c)
    return uniq


def print_banner():
    """打印脚本横幅"""
    banner = f"""
{C.CYAN}{C.BOLD}╔══════════════════════════════════════════════════════════════════╗
║         Cloudflare CDN IP 三网检测脚本 v1.0                        ║
║         ICMP RTT / 路由落地 / 多端口TCP RTT / 三网评估              ║
╚══════════════════════════════════════════════════════════════════╝{C.RESET}
"""
    print(banner)


def progress_bar(current, total, prefix='', width=38):
    """打印进度条"""
    if total == 0:
        return
    pct = current / total * 100
    filled = int(width * current / total)
    bar = C.GREEN + '#' * filled + C.DIM + '-' * (width - filled) + C.RESET
    sys.stdout.write(f'\r  {prefix} [{bar}] {current}/{total} ({pct:.0f}%)')
    sys.stdout.flush()
    if current >= total:
        print()


def rating_stars(score):
    """分数转星级"""
    if score >= 80:
        return f'{C.GREEN}★★★{C.RESET}'
    elif score >= 60:
        return f'{C.YELLOW}★★☆{C.RESET}'
    elif score >= 40:
        return f'{C.YELLOW}★☆☆{C.RESET}'
    else:
        return f'{C.RED}☆☆☆{C.RESET}'


def rtt_color(rtt):
    """RTT 值着色"""
    if rtt is None:
        return f'{C.RED}  超时{C.RESET}'
    if rtt < RTT_PREMIUM:
        return f'{C.GREEN}{rtt:>6.1f}ms{C.RESET}'
    elif rtt < RTT_GOOD:
        return f'{C.CYAN}{rtt:>6.1f}ms{C.RESET}'
    elif rtt < RTT_NORMAL:
        return f'{C.YELLOW}{rtt:>6.1f}ms{C.RESET}'
    else:
        return f'{C.RED}{rtt:>6.1f}ms{C.RESET}'


# ============================================================
# 网络检测函数
# ============================================================

def _decode_output(raw_bytes):
    """安全解码 subprocess 输出 (兼容 Windows GBK / UTF-8 / Latin-1)"""
    if raw_bytes is None:
        return ''
    # 依次尝试 UTF-8、GBK、Latin-1 (Latin-1 永不失败)
    for enc in ['utf-8', 'gbk', 'gb2312', 'latin-1']:
        try:
            return raw_bytes.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw_bytes.decode('latin-1')


def ping_rtt(ip, timeout=1.0, count=3):
    """
    ICMP Ping RTT 检测
    返回: (avg_rtt_ms, min_rtt_ms, max_rtt_ms, loss_rate) 或 (None, None, None, 100)

    使用纯 ASCII 正则匹配，兼容中英文 Windows locale 编码 (GBK/UTF-8)。
    """
    if IS_WINDOWS:
        cmd = ['ping', '-n', str(count), '-w', str(int(timeout * 1000)), ip]
    else:
        cmd = ['ping', '-c', str(count), '-W', str(int(timeout)), ip]

    try:
        result = subprocess.run(
            cmd, capture_output=True,
            timeout=timeout * count + 5,
        )
        output = _decode_output(result.stdout) + _decode_output(result.stderr)

        # 解析 RTT — 纯 ASCII 模式，不依赖 locale 文字
        # 匹配 "=153ms" / "=38.5ms" / "<1ms" (英文 time= / 中文 时间= 均含 "=")
        time_pattern = r'[=<](\d+\.?\d*)\s*ms'
        times = re.findall(time_pattern, output, re.IGNORECASE)

        if times:
            rtts = [float(t) for t in times]
            avg = sum(rtts) / len(rtts)
            return (avg, min(rtts), max(rtts), 0.0)

        # 检查丢包率 (百分比是纯 ASCII)
        # Windows: "(0% loss)" / 中文: "(0% 丢失)"  — "%" 前的数字是 ASCII
        loss_match = re.search(r'\((\d+)%\s', output)
        if loss_match:
            loss_rate = float(loss_match.group(1))
            if loss_rate < 100 and times:
                rtts = [float(t) for t in times]
                return (sum(rtts) / len(rtts), min(rtts), max(rtts), loss_rate)
            return (None, None, None, loss_rate)

        # 无匹配 — 超时或不可达
        return (None, None, None, 100.0)

    except subprocess.TimeoutExpired:
        return (None, None, None, 100.0)
    except Exception:
        return (None, None, None, 100.0)


def tcp_rtt(ip, port, timeout=2.0):
    """
    TCP 连接 RTT 检测
    返回: RTT (毫秒) 或 None
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(timeout)
    start = time.monotonic()
    try:
        sock.connect((ip, port))
        rtt = (time.monotonic() - start) * 1000
        return rtt
    except (socket.timeout, socket.error, OSError):
        return None
    finally:
        try:
            sock.close()
        except:
            pass


def tcp_rtt_multi_round(ip, port, rounds=4, timeout=2.0):
    """
    多轮 TCP RTT 检测 (参考 CloudflareST 的 4 次 TCPing)

    改进:
      - 多轮测试取中位数 (鲁棒抗异常)
      - IQR 方法剔除离群点 (如偶发的 1000ms+ 超时重传)
      - 计算 jitter (max-min) 评估稳定性

    返回: (median_rtt, min_rtt, jitter, valid_count, all_rtts)
        median_rtt: 中位数 RTT (毫秒), None 表示全部失败
        min_rtt:    最小 RTT
        jitter:     抖动 = filtered_max - filtered_min
        valid_count: 有效轮数
        all_rtts:   原始 RTT 列表 (调试用)
    """
    rtts = []
    for _ in range(rounds):
        rtt = tcp_rtt(ip, port, timeout)
        if rtt is not None:
            rtts.append(rtt)

    if not rtts:
        return (None, None, None, 0, [])

    # IQR 异常值过滤
    filtered = rtts
    if len(rtts) >= 4:
        sorted_rtts = sorted(rtts)
        q1 = sorted_rtts[len(sorted_rtts) // 4]
        q3 = sorted_rtts[3 * len(sorted_rtts) // 4]
        iqr = q3 - q1
        lower_bound = q1 - 1.5 * iqr
        upper_bound = q3 + 1.5 * iqr
        filtered = [r for r in rtts if lower_bound <= r <= upper_bound]
        if not filtered:
            filtered = rtts  # 全部被过滤时回退到原始值

    median_rtt = statistics.median(filtered)
    min_rtt = min(filtered)
    jitter = max(filtered) - min(filtered)

    return (median_rtt, min_rtt, jitter, len(filtered), rtts)


def get_cf_trace(ip, timeout=3.0):
    """
    通过 Cloudflare /cdn-cgi/trace 端点获取落地信息

    策略1: 原始 socket HTTP (最可靠, 能获取完整 trace body)
    策略2: HTTPS urllib (备选, 能从 cf-ray 头提取 colo)
    策略3: HTTP urllib + HTTPError 头提取 (最后手段)

    返回: dict 包含 colo, loc, ip 等字段, 或 None
    """
    # ---- 策略1: 原始 socket ----
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, 80))
        request = (
            'GET /cdn-cgi/trace HTTP/1.1\r\n'
            'Host: cloudflare.com\r\n'
            'User-Agent: cf-tri-net-detect/1.0\r\n'
            'Accept: text/plain, */*\r\n'
            'Connection: close\r\n'
            '\r\n'
        )
        sock.send(request.encode())
        response = b''
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            except socket.timeout:
                break
        sock.close()

        resp_str = response.decode('utf-8', errors='replace')
        headers_part, _, body = resp_str.partition('\r\n\r\n')

        # 从 body 解析 trace
        trace = {}
        for line in body.strip().split('\n'):
            if '=' in line:
                k, v = line.split('=', 1)
                trace[k.strip()] = v.strip()

        if 'colo' in trace:
            return trace

        # body 没有 colo, 从 cf-ray 头提取
        for line in headers_part.split('\r\n'):
            if line.lower().startswith('cf-ray:'):
                cf_ray = line.split(':', 1)[1].strip()
                parts = cf_ray.split('-')
                if len(parts) >= 2 and len(parts[-1]) == 3:
                    trace['colo'] = parts[-1]
                    return trace
    except Exception:
        pass

    # ---- 策略2: HTTPS urllib ----
    try:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        url = f'https://{ip}/cdn-cgi/trace'
        req = urllib.request.Request(url, headers={
            'User-Agent': 'cf-tri-net-detect/1.0',
            'Host': 'cloudflare.com',
        })
        resp = urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx)
        data = resp.read().decode('utf-8', errors='replace')

        trace = {}
        for line in data.strip().split('\n'):
            if '=' in line:
                k, v = line.split('=', 1)
                trace[k.strip()] = v.strip()

        if 'colo' in trace:
            return trace

        # 从 cf-ray 头提取
        cf_ray = resp.headers.get('cf-ray', '')
        if cf_ray:
            parts = cf_ray.split('-')
            if len(parts) >= 2 and len(parts[-1]) == 3:
                trace['colo'] = parts[-1]
                return trace
    except urllib.error.HTTPError as e:
        # 错误响应也可能有 cf-ray 头
        cf_ray = e.headers.get('cf-ray', '')
        if cf_ray:
            parts = cf_ray.split('-')
            if len(parts) >= 2 and len(parts[-1]) == 3:
                return {'colo': parts[-1]}
    except Exception:
        pass

    return None


# 记录每个 IP 的 traceroute 失败原因 (用于诊断 / 跨机器排查)
_tracert_errors = {}


def run_traceroute(ip, max_hops=15, timeout=2):
    """
    执行路由追踪

    返回: hops 列表 [(hop_num, ip, host, rtt_ms), ...] 或 None
      - host: 反查得到的主机名 (无则空字符串), 用于路由落地/骨干判断
      - 目标不可达时对应跳的 ip 记为 'unreachable' (不会计入有效路由分析)
    注意: 默认开启反查 (不加 -d/-n) 以获取主机名, 这是路由判断城市与
          三网骨干的关键依据。
    """
    _tracert_errors.pop(ip, None)

    def _run(cmd):
        try:
            # Windows tracert 在 Python 子进程下耗时通常是手动的 10-20x
            # (实际环境 12 跳需 60-100s), 公式 max_hops*timeout*3+30 给予足够缓冲
            result = subprocess.run(
                cmd, capture_output=True,
                timeout=max_hops * timeout * 3 + 30,
            )
            out = _decode_output(result.stdout) + '\n' + _decode_output(result.stderr)
            return out, result.returncode
        except Exception as e:
            return str(e), -1

    def _parse(out):
        hops = []
        for line in out.split('\n'):
            line = line.strip()
            if not line:
                continue
            # 匹配 hop 编号 (兼容 Windows "1  ..." / Linux "1  ..." / tracepath "1: ...")
            hop_match = re.match(r'^\s*(\d+)\s*[:.]?\s*(.*)', line)
            if not hop_match:
                continue
            hop_num = int(hop_match.group(1))
            rest = hop_match.group(2).strip()
            if not rest:
                continue

            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', rest)
            rtt_match = re.findall(r'(\d+)\s*ms', rest)

            if ip_match:
                hop_ip = ip_match.group(1)
                hop_rtt = float(rtt_match[0]) if rtt_match else None
                # 主机名: IP 之前的文本 (Windows "host [ip]" / Linux "host (ip)")
                host = rest.split(hop_ip)[0].strip(' \t()[]')
                hops.append((hop_num, hop_ip, host, hop_rtt))
            elif '*' in rest:
                hops.append((hop_num, '*', '', None))
            elif re.search(r'unreachable|no route|!h|!n|无法访问|不可达', rest, re.IGNORECASE):
                # 目标/网络不可达 (Windows "Destination host unreachable" 等)
                hops.append((hop_num, 'unreachable', '', None))
        return hops

    if IS_WINDOWS:
        # 不加 -d -> tracert 会反查主机名, 便于识别落地城市与骨干
        out, rc = _run(['tracert', '-h', str(max_hops), '-w', str(int(timeout * 1000)), ip])
    else:
        # 不加 -n -> traceroute 返回主机名
        out, rc = _run(['traceroute', '-m', str(max_hops), '-w', str(int(timeout)), ip])
        # Linux/Mac: traceroute 常需 root, 失败则退回 tracepath (通常无需 root)
        if not _parse(out):
            out2, _ = _run(['tracepath', '-m', str(max_hops), ip])
            if out2.strip():
                out = out + '\n' + out2

    hops = _parse(out)
    if not hops:
        # 记录失败原因, 便于跨机器排查 (权限/防火墙/不可达但无 * 行 等)
        low = out.lower()
        if 'must be root' in low or 'operation not permitted' in low or 'permission' in low:
            reason = 'traceroute 需要 root 权限 (Linux/Mac), 已尝试 tracepath 兜底仍失败'
        elif 'is not recognized' in low or 'not found' in low or 'no such file' in low:
            reason = 'traceroute/tracepath 命令不存在或不在 PATH'
        elif 'destination host unreachable' in low or 'destination net unreachable' in low \
                or '无法访问' in out or '不可达' in out:
            reason = '目标不可达 (Destination unreachable) — 该网络无法路由到此 IP'
        elif 'timed out' in low or '请求超时' in out or 'general failure' in low:
            reason = 'traceroute 超时/被防火墙拦截 (ICMP 被丢弃)'
        else:
            reason = 'traceroute 无可用跳数输出 (返回码 %s)' % rc
        _tracert_errors[ip] = reason
        return None

    return hops


# ============================================================
# 路由跳数分析: 落地城市推断 + 三网骨干识别
# ============================================================

# 落地城市推断模式 (匹配末 3-5 跳的主机名/IP)
# key -> (中文城市名, [正则模式列表])
ROUTE_LANDING_PATTERNS = {
    'HKG': ('中国香港', [
        r'hkg', r'hong\s*kong', r'(?:^|[^a-z])hk(?:[^a-z]|$)', r'as58453', r'as9304', r'hkix',
    ]),
    'NRT': ('日本东京', [
        r'nrt', r'tokyo', r'tokyjp', r'(?:^|[^a-z])jp(?:[^a-z]|$)', r'kddi', r'(?:^|[^a-z])iij(?:[^a-z]|$)', r'as2516',
    ]),
    'SIN': ('新加坡', [
        r'singapore', r'singnet', r'(?:^|[^a-z])sg(?:[^a-z]|$)', r'as7473', r'as45143',
    ]),
    'LAX': ('美国洛杉矶', [
        r'(?:^|[^a-z])lax(?:[^a-z]|$)', r'los\s*angeles', r'lax1',
    ]),
    'SFO': ('美国旧金山', [
        r'(?:^|[^a-z])sfo(?:[^a-z]|$)', r'san\s*francisco', r'san\s*jose', r'(?:^|[^a-z])sjc(?:[^a-z]|$)',
    ]),
    'FRA': ('德国法兰克福', [
        r'(?:^|[^a-z])fra(?:[^a-z]|$)', r'frankfurt', r'as3257', r'de-cix',
    ]),
    'AMS': ('荷兰阿姆斯特丹', [
        r'(?:^|[^a-z])ams(?:[^a-z]|$)', r'amsterdam', r'as1299',
    ]),
}

# 三网骨干识别模式 (增强版: 融合 backtrace 启发式前缀 + GeoLite2 ASN mmdb)
# 参考: github.com/zhanghanyun/backtrace 的 ipAsn() 算法
TRI_NET_BACKBONE_PATTERNS = {
    'telecom': {
        'name': '电信',
        'ip_prefix': ('202.97.', '59.43.', '202.101.', '202.120.', '202.112.', '202.96.', '218.30.', '220.181.'),
        'host_kw': ('chinanet', 'cn2', 'ctgw', 'telecom', 'china-telecom', '163.gd', '163.com'),
        'asn': ('as4134', 'as4809'),   # ChinaNet / CN2
        'premium_ip': ('59.43.',),     # CN2 = 优质电信
        'premium_asn': ('as4809',),
        'boost': 25,
    },
    'unicom': {
        'name': '联通',
        'ip_prefix': ('219.158.', '221.4.', '221.5.', '221.6.', '221.7.', '221.8.', '125.'),
        'host_kw': ('unicom', 'cnc', 'cu.', 'cucloud', 'chinaunicom'),
        'asn': ('as4837', 'as9929'),   # China Unicom 骨干 / CUII
        'premium_ip': (),
        'premium_asn': ('as9929',),    # CUII / "9929" 优质
        'boost': 25,
    },
    'mobile': {
        'name': '移动',
        'ip_prefix': ('211.136.', '211.137.', '211.138.', '211.139.', '221.176.', '221.177.', '111.24.', '120.196.', '183.230.'),
        'host_kw': ('mobile', 'cmcc', 'chinamobile', 'ctg', 'cm.'),
        'asn': ('as9808', 'as56040'),  # China Mobile / CMCC-GIF
        'premium_ip': (),
        'premium_asn': ('as56040',),   # CMCC-GIF 优质
        'boost': 25,
    },
}

# ============================================================
# 三网回程线路分类 —— 移植自 oneclickvirt/backtrace
# 参考源码 (main 分支):
#   bk/ipv4_asn.go            IPv4 前缀 -> ASN (ipv4Asn)
#   bk/model/model.go         ASN -> 线路标签/层级 (M 表)
#   bk/route_classification.go 回程 ASN 顺序/跳数 -> 线路 + 置信度
# 该项目的核心能力: 对联通 9929/4837、电信 CN2/163/CTGNET、移动 CMIN2/CMI/CMNET
# 等线路做自动分析, 并依据 ASN 在回程中的出现顺序与跳数判定精确线路与置信度。
# ============================================================

# IPv4 前缀 -> ASN (逐字移植 backtrace bk/ipv4_asn.go)
# 这是 backtrace 对三大运营商骨干的权威分类表
BACKTRACE_PREFIX_ASN = [
    ('59.43',   'AS4809'),   # 电信 CN2
    ('202.97',  'AS4134'),   # 电信 163 (ChinaNet)
    ('218.105', 'AS9929'),   # 联通 9929 (CUII / A 网)
    ('210.51',  'AS9929'),   # 联通 9929
    ('202.77',  'AS10099'),  # 联通 CUG (国际)
    ('43.252',  'AS10099'),  # 联通 CUG
    ('61.14',   'AS10099'),  # 联通 CUG
    ('219.158', 'AS4837'),   # 联通 4837 (China169 骨干)
    ('223.118', 'AS58453'),  # 移动 CMI 国际
    ('223.119', 'AS58453'),  # 移动 CMI 国际
    ('223.120', 'AS58453'),  # 移动 CMI 国际
    ('223.121', 'AS58453'),  # 移动 CMI 国际
    ('221.183', 'AS9808'),   # 移动 CMNET 国内骨干
    ('111.24',  'AS9808'),   # 移动 CMNET 国内骨干
    ('69.194',  'AS23764'),  # 电信 CTGNET
    ('203.22',  'AS23764'),  # 电信 CTGNET
]


def is_cmin2_ipv4(o):
    """移植 backtrace bk/ipv4_asn.go 的 isCMIN2IPv4(): 判断是否为移动 CMIN2 精品段。"""
    if o[0] != 223:
        return False
    if o[1] == 118 and o[2] == 32:
        return True
    if o[1] == 120 and o[2] >= 128:
        return True
    if o[1] != 119:
        return False
    t = o[2]
    return (t in (8, 9)
            or (10 <= t <= 15)
            or (26 <= t <= 29)
            or (32 <= t <= 37)
            or t in (74, 75, 88, 89, 100, 252, 253))


def ipv4_asn(ip_str):
    """
    逐字移植 backtrace bk/ipv4_asn.go 的 ipv4Asn(): IPv4 地址 -> ASN 字符串。
    覆盖三大运营商核心骨干段; 命中返回 'ASxxxx', 否则返回 ''。
    注意 CMIN2(AS58807) 的判定优先于 223.118/119/120/121 -> AS58453(CMI)。
    """
    if not ip_str or ':' in ip_str:
        return ''  # 本项目聚焦 IPv4; IPv6 走 GeoLite2 回退
    parts = ip_str.split('.')
    if len(parts) != 4:
        return ''
    try:
        o = tuple(int(x) for x in parts)
    except ValueError:
        return ''
    if o[0] == 59 and o[1] == 43:
        return 'AS4809'
    if o[0] == 202 and o[1] == 97:
        return 'AS4134'
    if (o[0] == 218 and o[1] == 105) or (o[0] == 210 and o[1] == 51):
        return 'AS9929'
    if (o[0] == 202 and o[1] == 77) or (o[0] == 43 and o[1] == 252) or (o[0] == 61 and o[1] == 14):
        return 'AS10099'
    if o[0] == 219 and o[1] == 158:
        return 'AS4837'
    if is_cmin2_ipv4(o):
        return 'AS58807'
    if o[0] == 223 and o[1] in (118, 119, 120, 121):
        return 'AS58453'
    if (o[0] == 221 and o[1] == 183) or (o[0] == 111 and o[1] == 24):
        return 'AS9808'
    if (o[0] == 69 and o[1] == 194) or (o[0] == 203 and o[1] == 22):
        return 'AS23764'
    return ''


# ASN -> (运营商代码, 基础线路名, 层级, 中文标签)
# 移植自 backtrace bk/model/model.go 的 M 表 (AS4809a/b 的细分在 route 判定中处理)
ASN_LINE_INFO = {
    'AS23764': ('CT', 'CTGNET', 'premium', '电信CTGNET [精品线路]'),
    'AS4809':  ('CT', 'CN2',    'premium', '电信CN2    [优质线路]'),
    'AS4134':  ('CT', '163',    'normal',  '电信163    [普通线路]'),
    'AS9929':  ('CU', '9929',   'premium', '联通9929   [优质线路]'),
    'AS10099': ('CU', 'CUG',    'premium', '联通CUG    [优质线路]'),
    'AS4837':  ('CU', '4837',   'normal',  '联通4837   [普通线路]'),
    'AS58807': ('CM', 'CMIN2',  'premium', '移动CMIN2  [精品线路]'),
    'AS9808':  ('CM', 'CMNET',  'normal',  '移动CMNET  [普通线路]'),
    'AS58453': ('CM', 'CMI',    'normal',  '移动CMI    [普通线路]'),
}

CARRIER_TO_ISP = {'CT': 'telecom', 'CU': 'unicom', 'CM': 'mobile'}
ISP_TO_CARRIER = {'telecom': 'CT', 'unicom': 'CU', 'mobile': 'CM'}

# 分类 code -> 基础线路标识 (用于评分/兼容; 精确中文标签见 _classify_* 返回值)
_CODE_TO_LINE = {
    'ct_cn2_gia': 'CN2GIA', 'ct_cn2_gt': 'CN2GT', 'ct_cn2_mixed': 'CN2混合',
    'ct_ctgnet': 'CTGNET', 'ct_163': '163',
    'cu_9929': '9929', 'cu_9929_mixed': '9929混合', 'cu_cug': 'CUG', 'cu_4837': '4837',
    'cm_cmin2': 'CMIN2', 'cm_cmin2_mixed': 'CMIN2混合', 'cm_cmi': 'CMI', 'cm_cmnet': 'CMNET',
}


def classify_hop_ip(ip_str):
    """
    对单跳 IPv4 做线路分类 (backtrace 前缀优先, GeoLite2 ASN mmdb 回退)。

    返回: (isp, line, asn, quality) 或 None
        isp: 'telecom' / 'unicom' / 'mobile'
        line: 'CN2' / '163' / '9929' / '4837' / 'CMIN2' / 'CMI' / 'CMNET' / 'CTGNET' / 'CUG'
        asn: 'AS4809' 等
        quality: 'premium' (精品/优质) / 'normal' (普通)
    """
    # 策略1: backtrace IPv4 前缀表 (最快, 覆盖核心特征段)
    asn = ipv4_asn(ip_str)
    if asn:
        info = ASN_LINE_INFO.get(asn)
        if info:
            carrier, line, tier, _label = info
            return (CARRIER_TO_ISP[carrier], line, asn, tier)

    # 策略2: GeoLite2 ASN mmdb 精确查询 (覆盖新段位 / 非特征段)
    geoip = GeoIPReader.get()
    if geoip and geoip.asn_reader:
        asn_num, asn_org = geoip.lookup_asn(ip_str)
        if asn_num:
            asn_str = f'AS{asn_num}'
            info = ASN_LINE_INFO.get(asn_str)
            if info:
                carrier, line, tier, _label = info
                return (CARRIER_TO_ISP[carrier], line, asn_str, tier)
            # 尝试组织名关键字匹配 (mmdb 有 ASN 但不在固定表里)
            org_lower = (asn_org or '').lower()
            if 'next generation' in org_lower or ' cn2' in org_lower:
                return ('telecom', 'CN2', asn_str, 'premium')
            if 'chinanet' in org_lower or 'china telecom' in org_lower:
                return ('telecom', '163', asn_str, 'normal')
            if 'china169' in org_lower or 'unicom' in org_lower:
                if asn_num == 9929 or asn_num == 10099:
                    return ('unicom', '9929', asn_str, 'premium')
                return ('unicom', '4837', asn_str, 'normal')
            if 'china mobile' in org_lower or 'cmcc' in org_lower:
                return ('mobile', 'CMI', asn_str, 'normal')

    return None


# ============================================================
# 回程线路判定 —— 移植自 oneclickvirt/backtrace bk/route_classification.go
# 核心思想: 不仅看"出现了哪个 ASN", 更看 ASN 在回程中的出现顺序与跳数,
# 据此区分 CN2GIA/CN2GT/混合、9929/4837 前后关系, 并要求优质骨干 >=2 跳才确认
# (避免把单一目的网投递跳误判为骨干)。最终给出置信度 confirmed/mixed/inconclusive。
# ============================================================

def _normalize_carrier(value):
    value = (value or '').upper().strip()
    if value in ('CT', 'TELECOM', '电信'):
        return 'CT'
    if value in ('CU', 'UNICOM', '联通'):
        return 'CU'
    if value in ('CM', 'CMCC', 'MOBILE', '移动'):
        return 'CM'
    return value


def _route_asn_position(hop_asns, target):
    """返回 target ASN 首次出现的跳索引与出现次数 (移植 routeASNPosition)。"""
    first = -1
    count = 0
    for idx, asns in enumerate(hop_asns):
        if any(a.upper().strip() == target for a in asns):
            if first < 0:
                first = idx
            count += 1
    return first, count


def classify_return_route(carrier, hop_asns):
    """
    判定某个运营商在回程中实际使用的线路与置信度 (移植 ClassifyReturnRoute)。

    carrier: 'telecom'/'unicom'/'mobile' (或 'CT'/'CU'/'CM')
    hop_asns: 有序列表, 每个元素是该跳观察到的运营商 ASN 字符串列表 (与回程顺序一致; 空跳为 [])

    返回: (code, label, confidence, rank, evidence)
      confidence: 'confirmed' / 'mixed' / 'inconclusive'
      rank: 5=最高(精品) 4=精品 3=优质混合 2=普通 0=证据不足
    """
    carrier = _normalize_carrier(carrier)
    if carrier == 'CT':
        return _classify_telecom(hop_asns)
    if carrier == 'CU':
        return _classify_unicom(hop_asns)
    if carrier == 'CM':
        return _classify_mobile(hop_asns)
    return ('unknown_carrier', '线路证据不足', 'inconclusive', 0, 'unknown carrier')


def _classify_telecom(hops):
    cn2_index, cn2_hops = _route_asn_position(hops, 'AS4809')
    ct163_index, ct163_hops = _route_asn_position(hops, 'AS4134')
    ctg_index, _ = _route_asn_position(hops, 'AS23764')
    if cn2_index >= 0:
        if cn2_hops < 2:
            return ('ct_cn2_mixed', '电信CN2混合 [优质线路]', 'mixed', 3, 'only one AS4809 hop; CN2 GIA is not confirmed')
        if ct163_index < 0 or (cn2_index < ct163_index and ct163_hops <= 1):
            return ('ct_cn2_gia', '电信CN2GIA [精品线路]', 'confirmed', 5, 'at least two AS4809 hops precede at most one AS4134 delivery hop')
        if cn2_index < ct163_index:
            return ('ct_cn2_mixed', '电信CN2混合 [优质线路]', 'mixed', 3, 'AS4809 is followed by multiple AS4134 backbone hops')
        return ('ct_cn2_gt', '电信CN2GT  [优质线路]', 'mixed', 3, 'AS4134 appears before the AS4809 segment')
    if ctg_index >= 0:
        return ('ct_ctgnet', '电信CTGNET [精品线路]', 'confirmed', 4, 'AS23764 is present')
    if ct163_index >= 0:
        if ct163_hops <= 1:
            return ('ct_destination_only', '仅见电信目的网', 'inconclusive', 0, 'only one AS4134 hop')
        return ('ct_163', '电信163    [普通线路]', 'confirmed', 2, 'multiple AS4134 hops are present without premium backbone evidence')
    return ('ct_unknown', '未见电信骨干', 'inconclusive', 0, 'AS4809, AS23764, and AS4134 are absent')


def _classify_unicom(hops):
    cu9929_index, _ = _route_asn_position(hops, 'AS9929')
    cug_index, _ = _route_asn_position(hops, 'AS10099')
    cu4837_index, cu4837_hops = _route_asn_position(hops, 'AS4837')
    if cu9929_index >= 0:
        if cu4837_index >= 0 and cu4837_index < cu9929_index:
            return ('cu_9929_mixed', '联通9929混合 [优质线路]', 'mixed', 3, 'AS4837 appears before the AS9929 segment')
        return ('cu_9929', '联通9929   [优质线路]', 'confirmed', 5, 'AS9929 is present without an earlier AS4837 segment')
    if cug_index >= 0:
        return ('cu_cug', '联通CUG    [优质线路]', 'confirmed', 3, 'AS10099 is present without AS9929')
    if cu4837_index >= 0:
        if cu4837_hops <= 1:
            return ('cu_destination_only', '仅见联通目的网', 'inconclusive', 0, 'only one AS4837 hop')
        return ('cu_4837', '联通4837   [普通线路]', 'confirmed', 2, 'multiple AS4837 hops are present without premium backbone evidence')
    return ('cu_unknown', '未见联通骨干', 'inconclusive', 0, 'AS9929, AS10099, and AS4837 are absent')


def _classify_mobile(hops):
    cmin2_index, _ = _route_asn_position(hops, 'AS58807')
    cmi_index, _ = _route_asn_position(hops, 'AS58453')
    cmnet_index, _ = _route_asn_position(hops, 'AS9808')
    if cmin2_index >= 0:
        if cmi_index >= 0 and cmi_index < cmin2_index:
            return ('cm_cmin2_mixed', '移动CMIN2混合 [优质线路]', 'mixed', 3, 'AS58453 appears before the AS58807 segment')
        return ('cm_cmin2', '移动CMIN2  [精品线路]', 'confirmed', 5, 'AS58807 is present without an earlier AS58453 segment')
    if cmi_index >= 0:
        return ('cm_cmi', '移动CMI    [普通线路]', 'confirmed', 2, 'AS58453 is present without CMIN2 evidence')
    if cmnet_index >= 0:
        return ('cm_cmnet', '移动CMNET  [普通线路]', 'confirmed', 2, 'AS9808 is present without international premium backbone evidence')
    return ('cm_unknown', '未见移动骨干', 'inconclusive', 0, 'AS58807, AS58453, and AS9808 are absent')


def analyze_route_hops(hops):
    """
    分析 traceroute 跳数: 推断落地城市 + 识别三网骨干

    增强版: 融合 backtrace 启发式前缀匹配 + GeoLite2 ASN mmdb 精确查询
    参考: github.com/zhanghanyun/backtrace 的 ipAsn() 算法

    参数: hops = [(hop_num, ip, host, rtt), ...]  (来自 run_traceroute)

    返回 dict:
      route_landing       : 推测落地城市(中文), 无则 ''
      route_landing_code  : 落地代码(HKG/NRT/...), 无则 ''
      route_landing_evidence: 命中证据字符串, 无则 ''
      tri_net             : {
          'telecom': {'detected': bool, 'evidence': str, 'premium': bool, 'line': str, 'asn': str},
          'unicom':  {...},
          'mobile':  {...},
      }
      route_asn_path      : ASN 路径列表 [(hop, ip, asn, org, line, quality), ...]
    """
    empty_tri = {
        'telecom': {'detected': False, 'code': '', 'label': '', 'line': '', 'asn': '',
                    'confidence': 'inconclusive', 'rank': 0, 'premium': False, 'evidence': ''},
        'unicom':  {'detected': False, 'code': '', 'label': '', 'line': '', 'asn': '',
                    'confidence': 'inconclusive', 'rank': 0, 'premium': False, 'evidence': ''},
        'mobile':  {'detected': False, 'code': '', 'label': '', 'line': '', 'asn': '',
                    'confidence': 'inconclusive', 'rank': 0, 'premium': False, 'evidence': ''},
    }
    if not hops:
        return {
            'route_landing': '', 'route_landing_code': '', 'route_landing_evidence': '',
            'tri_net': empty_tri,
            'route_asn_path': [],
        }

    # 有效跳 (有 IP 的; 排除超时 '*' 与不可达 'unreachable')
    valid = [(h[1], (h[2] or '').lower()) for h in hops if h[1] not in ('*', 'unreachable') and h[1]]
    # 末 3-5 跳 (落地城市主要看靠近目标的一侧)
    tail = valid[-5:]

    # ---- 落地城市推断 (扫描末 5 跳, 同时用 GeoLite2 Country 辅助) ----
    route_landing = ''
    route_landing_code = ''
    route_landing_evidence = ''
    for idx, (ip, host) in enumerate(tail):
        text = f'{host} {ip}'
        for code, (city_cn, patterns) in ROUTE_LANDING_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, text, re.IGNORECASE):
                    route_landing = city_cn
                    route_landing_code = code
                    route_landing_evidence = f'{host or ip} (末第{len(tail)-idx}跳, 命中 {pat})'
                    break
            if route_landing:
                break

    # ---- 三网骨干识别 (移植 oneclickvirt/backtrace 的 ASN 顺序/跳数判定) ----
    # 对每跳 IP 做分类, 收集 ASN 路径; 同时记录逐跳 ASN 序列 (保留回程位置, 空跳用 [])
    route_asn_path = []
    hop_asns = []            # 有序: 每跳观察到的运营商 ASN 列表 (与回程顺序一致)
    carrier_evidence = {     # 各运营商命中跳的 (ip, asn) 收集, 用于证据展示
        'telecom': [], 'unicom': [], 'mobile': [],
    }

    geoip = GeoIPReader.get()
    for hop_idx, (ip, host) in enumerate(valid):
        result = classify_hop_ip(ip)
        if result:
            isp, line_name, asn_str, quality = result
            hop_info = {
                'hop': hop_idx + 1,
                'ip': ip,
                'host': host,
                'asn': asn_str,
                'line': line_name,
                'quality': quality,
                'isp': isp,
            }
            # 补充 ASN 组织名
            if geoip and geoip.asn_reader:
                _, org = geoip.lookup_asn(ip)
                hop_info['org'] = org or ''
            else:
                hop_info['org'] = ''
            route_asn_path.append(hop_info)
            hop_asns.append([asn_str])
            carrier_evidence[isp].append((ip, asn_str))
        else:
            hop_asns.append([])

    # 逐运营商按回程 ASN 顺序/跳数做精确线路判定 (backtrace route_classification.go)
    tri_net = {k: dict(v) for k, v in empty_tri.items()}  # 深拷贝
    for isp, carrier in (('telecom', 'CT'), ('unicom', 'CU'), ('mobile', 'CM')):
        code, label, confidence, rank, _ev = classify_return_route(carrier, hop_asns)
        detected = confidence != 'inconclusive' and rank > 0
        line = _CODE_TO_LINE.get(code, '')
        tier = 'premium' if rank >= 3 else 'normal'
        # 证据: 该运营商命中的 ASN 跳 (去重 IP)
        ev_list = carrier_evidence[isp]
        asns_seen = []
        ev_ips = []
        for ip, asn_str in ev_list:
            if asn_str not in asns_seen:
                asns_seen.append(asn_str)
            if ip not in ev_ips:
                ev_ips.append(ip)
        tri_net[isp] = {
            'detected': detected,
            'code': code,
            'label': label if detected else '',
            'line': line if detected else '',
            'asn': '/'.join(asns_seen) if asns_seen else '',
            'confidence': confidence,
            'rank': rank,
            'premium': detected and tier == 'premium',
            'evidence': ', '.join(ev_ips) if ev_ips else '',
        }

    return {
        'route_landing': route_landing,
        'route_landing_code': route_landing_code,
        'route_landing_evidence': route_landing_evidence,
        'tri_net': tri_net,
        'route_asn_path': route_asn_path,
    }


# ============================================================
# ISP 检测
# ============================================================

def detect_local_isp():
    """
    检测本地网络 ISP 信息
    返回: dict {ip, city, isp, country} 或 None
    """
    # 方法1: 通过 ip.sb API
    apis = [
        ('https://api.ip.sb/geoip', 'ip.sb'),
        ('https://ipinfo.io/json', 'ipinfo.io'),
        ('https://api.ip.sb/geoip/all', 'ip.sb-all'),
    ]

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    for url, name in apis:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'cf-detect/1.0'})
            resp = urllib.request.urlopen(req, timeout=5, context=ssl_ctx)
            data = json.loads(resp.read().decode('utf-8'))

            isp = data.get('isp', data.get('org', data.get('organization', '')))
            city = data.get('city', '')
            country = data.get('country', data.get('country_code', ''))
            ip = data.get('ip', data.get('query', ''))

            # 中文 ISP 名称映射
            isp_lower = (isp or '').lower()
            if any(k in isp_lower for k in ['china telecom', 'chinanet', '电信', '163']):
                isp_cn = '中国电信'
            elif any(k in isp_lower for k in ['china unicom', 'unicom', '联通']):
                isp_cn = '中国联通'
            elif any(k in isp_lower for k in ['china mobile', 'mobile', '移动', 'cmcc']):
                isp_cn = '中国移动'
            elif any(k in isp_lower for k in ['cernet', '教育网']):
                isp_cn = '教育网'
            else:
                isp_cn = isp or '未知'

            return {
                'ip': ip,
                'city': city,
                'country': country,
                'isp': isp,
                'isp_cn': isp_cn,
                'source': name,
            }
        except Exception:
            continue

    return {'ip': '', 'city': '', 'country': '', 'isp': '', 'isp_cn': '未知', 'source': ''}


# ============================================================
# 三网评分 & 线路分类
# ============================================================

def score_three_network(colo, icmp_rtt, tcp_avg_rtt=None, tri_net=None):
    """
    基于落地数据中心、RTT 与(可选)实测三网骨干评估三网适配性

    参数:
        tri_net: analyze_route_hops() 返回的三网骨干 dict, 若某网络实测命中骨干,
                 则显著抬升该网络评分 (因为路由实测经过该运营商骨干)

    返回: dict {
        'unicom':  {'score': int, 'rating': str, 'backbone': str},
        'telecom': {'score': int, 'rating': str, 'backbone': str},
        'mobile':  {'score': int, 'rating': str, 'backbone': str},
    }
    """
    # 基础分 (按 colo 查表)
    base = THREE_NET_BASE_SCORES.get(colo, {'unicom': 45, 'telecom': 45, 'mobile': 45})

    # RTT 加分/扣分
    ref_rtt = tcp_avg_rtt if tcp_avg_rtt else (icmp_rtt if icmp_rtt else 300)
    if ref_rtt < 50:
        rtt_adj = 20
    elif ref_rtt < 80:
        rtt_adj = 12
    elif ref_rtt < 130:
        rtt_adj = 5
    elif ref_rtt < 200:
        rtt_adj = -5
    elif ref_rtt < 300:
        rtt_adj = -15
    else:
        rtt_adj = -30

    result = {}
    for isp in ['unicom', 'telecom', 'mobile']:
        score = max(0, min(100, base[isp] + rtt_adj))
        backbone = ''
        result[isp] = {
            'score': score,
            'rating': rating_stars(score),
            'backbone': backbone,
        }

    # 实测骨干命中 -> 抬升对应网络评分
    if tri_net:
        for isp in ['unicom', 'telecom', 'mobile']:
            info = tri_net.get(isp)
            if info and info.get('detected'):
                boost = TRI_NET_BACKBONE_PATTERNS[isp]['boost']
                cur = result[isp]['score']
                if info.get('premium'):
                    # 优质骨干 (CN2 / 9929 / 56040): 直接抬到 85+
                    new_score = max(cur, 88)
                else:
                    new_score = max(cur, min(100, cur + boost))
                    new_score = max(new_score, 70)  # 命中骨干至少 70
                result[isp]['score'] = new_score
                result[isp]['rating'] = rating_stars(new_score)
                label = (info.get('label') or '').strip()
                conf = info.get('confidence', '')
                conf_txt = ' [已确认]' if conf == 'confirmed' else (' [混合]' if conf == 'mixed' else '')
                result[isp]['backbone'] = f'{label}{conf_txt}:{info.get("evidence", "")}'

    return result


def classify_route(icmp_rtt, tcp_rtts, colo, hop_count=None):
    """
    综合评级线路质量

    返回: (quality_level, quality_score, description)
        quality_level: 'premium' | 'good' | 'normal' | 'poor'
        quality_score: 0-100
        description: 中文描述
    """
    score = 50
    factors = []

    # 因素1: ICMP RTT
    if icmp_rtt is not None:
        if icmp_rtt < RTT_PREMIUM:
            score += 25
            factors.append('ICMP延迟低')
        elif icmp_rtt < RTT_GOOD:
            score += 15
            factors.append('ICMP延迟良好')
        elif icmp_rtt < RTT_NORMAL:
            score += 5
        elif icmp_rtt < RTT_POOR:
            score -= 10
            factors.append('ICMP延迟偏高')
        else:
            score -= 25
            factors.append('ICMP延迟过高')
    else:
        score -= 30
        factors.append('ICMP无响应')

    # 因素2: TCP RTT 一致性
    valid_tcp = [v for v in tcp_rtts.values() if v is not None]
    if valid_tcp:
        tcp_avg = sum(valid_tcp) / len(valid_tcp)
        if len(valid_tcp) >= 2:
            tcp_var = max(valid_tcp) - min(valid_tcp)
            tcp_ratio = tcp_avg / max(icmp_rtt, 1) if icmp_rtt else 2.0

            if tcp_ratio < TCP_ICMP_RATIO_GOOD and tcp_var < 20:
                score += 20
                factors.append('TCP延迟稳定')
            elif tcp_ratio < TCP_ICMP_RATIO_OK:
                score += 8
                factors.append('TCP延迟正常')
            else:
                score -= 15
                factors.append('TCP延迟波动大')

        if tcp_avg < RTT_PREMIUM:
            score += 5
    else:
        score -= 15
        factors.append('TCP连接失败')

    # 因素3: 落地数据中心
    premium_colos = {'HKG', 'NRT', 'KIX', 'SIN', 'TPE', 'ICN'}
    if colo in premium_colos:
        score += 10
        factors.append(f'落地{CF_COLO_MAP.get(colo, ("?","",""))[2]}')
    elif colo in {'LAX', 'SJC', 'SFO'}:
        score += 0
    else:
        score -= 5

    # 因素4: 路由跳数
    if hop_count is not None:
        if hop_count <= 8:
            score += 8
            factors.append(f'路由跳数少({hop_count})')
        elif hop_count <= 12:
            score += 2
        elif hop_count <= 16:
            score -= 5
            factors.append(f'路由跳数多({hop_count})')
        else:
            score -= 15
            factors.append(f'路由跳数过多({hop_count})')

    score = max(0, min(100, score))

    if score >= 80:
        return ('premium', score, '优质线路 - ' + '，'.join(factors))
    elif score >= 60:
        return ('good', score, '良好线路 - ' + '，'.join(factors))
    elif score >= 40:
        return ('normal', score, '普通线路 - ' + '，'.join(factors))
    else:
        return ('poor', score, '较差线路 - ' + '，'.join(factors))


def check_cf_optimization(quality_level, quality_score, tcp_rtts, colo):
    """
    判断是否适合做 Cloudflare 优选
    条件: 线路质量 >= 良好, TCP 80/443 可用, 落地数据中心在亚太
    """
    if quality_level in ('poor',):
        return False, '线路质量差，不适合优选'

    if quality_level == 'normal' and quality_score < 45:
        return False, '线路质量普通，不推荐优选'

    # 检查标准端口可用性
    port_80 = tcp_rtts.get(80)
    port_443 = tcp_rtts.get(443)
    if port_80 is None and port_443 is None:
        return False, '80/443 端口不可用'

    # 检查落地位置
    asia_colos = {'HKG', 'NRT', 'KIX', 'SIN', 'TPE', 'ICN', 'BKK', 'KUL', 'MNL'}
    us_west = {'LAX', 'SJC', 'SFO', 'SEA', 'PDX'}

    if colo in asia_colos:
        return True, f'落地亚太({colo})，适合优选'
    elif colo in us_west and quality_score >= 65:
        return True, f'落地美西({colo})，质量达标可优选'
    elif quality_score >= 70:
        return True, f'线路质量达标，可尝试优选'
    else:
        return False, f'落地{colo}，延迟较高不推荐'


def check_rare_premium(quality_level, quality_score, icmp_rtt, tcp_rtts, colo):
    """
    判断是否属于稀有优质段
    条件: 优质线路 + RTT极低 + TCP稳定 + 落地亚太优质节点
    """
    if quality_level != 'premium':
        return False, ''

    if quality_score < 85:
        return False, ''

    if icmp_rtt is None or icmp_rtt >= 80:
        return False, ''

    rare_colos = {'HKG', 'NRT', 'KIX', 'SIN'}
    if colo not in rare_colos:
        return False, ''

    valid_tcp = [v for v in tcp_rtts.values() if v is not None]
    if len(valid_tcp) < 4:
        return False, ''

    tcp_avg = sum(valid_tcp) / len(valid_tcp)
    tcp_var = max(valid_tcp) - min(valid_tcp)

    if tcp_avg > 100:
        return False, ''
    if tcp_var > 15:
        return False, ''

    return True, f'稀有优质段: {colo}落地, RTT={icmp_rtt:.0f}ms, TCP均={tcp_avg:.0f}ms, 波动={tcp_var:.0f}ms'


# ============================================================
# 加权综合评分 (融合延迟/稳定性/下载速度/路由质量/落地)
# ============================================================

def composite_score(icmp_rtt, tcp_median_rtt, tcp_jitter, download_speed_mb,
                    route_quality, colo, port_443_ok=True):
    """
    加权综合评分 (0-100), 参考 CloudflareST 两段式 + backtrace 路由质量

    权重分配:
      - 下载速度 30%  (最终用户体验最核心指标)
      - 延迟       25%  (ICMP + TCP 中位数)
      - 路由质量   20%  (CN2/9929/CMIN2 = premium, 163/4837/CMI = normal)
      - 稳定性     15%  (jitter 越小越稳定)
      - 落地节点   10%  (亚太优质 colo 加分)

    参数:
        download_speed_mb: 下载速度 (MB/s), None 或 0 表示未测速
        route_quality: 'premium' / 'normal' / 'unknown'
        colo: CF 数据中心代码
        port_443_ok: 443 端口是否可达

    返回: (total_score, score_breakdown_dict)
    """
    # 延迟评分 (0-100)
    ref_rtt = tcp_median_rtt if tcp_median_rtt else icmp_rtt
    if ref_rtt is None:
        lat_score = 0
    elif ref_rtt < 50:
        lat_score = 100
    elif ref_rtt < 80:
        lat_score = 88
    elif ref_rtt < 130:
        lat_score = 72
    elif ref_rtt < 200:
        lat_score = 50
    elif ref_rtt < 300:
        lat_score = 25
    else:
        lat_score = 5

    # 稳定性评分 (0-100) — 基于 jitter
    if tcp_jitter is None:
        stab_score = 30
    elif tcp_jitter < 3:
        stab_score = 100
    elif tcp_jitter < 8:
        stab_score = 88
    elif tcp_jitter < 15:
        stab_score = 72
    elif tcp_jitter < 30:
        stab_score = 50
    elif tcp_jitter < 60:
        stab_score = 25
    else:
        stab_score = 5

    # 下载速度评分 (0-100)
    if download_speed_mb is None or download_speed_mb <= 0:
        speed_score = 0
    elif download_speed_mb >= 30:
        speed_score = 100
    elif download_speed_mb >= 20:
        speed_score = 88
    elif download_speed_mb >= 15:
        speed_score = 75
    elif download_speed_mb >= 10:
        speed_score = 60
    elif download_speed_mb >= 5:
        speed_score = 40
    else:
        speed_score = 15

    # 路由质量评分 (0-100)
    route_score_map = {
        'premium': 100,   # CN2 GIA / 9929 / CMIN2
        'good': 75,       # CN2 GT / 混合优质
        'normal': 50,     # 163 / 4837 / CMI
        'poor': 20,       # 绕路严重
        'unknown': 40,    # 未检测到
    }
    route_score = route_score_map.get(route_quality, 40)

    # 落地节点评分 (0-100)
    premium_colos = {'HKG', 'NRT', 'KIX', 'SIN', 'TPE', 'ICN'}
    good_colos = {'LAX', 'SJC', 'SFO', 'SEA', 'BKK', 'KUL', 'MNL', 'CGK', 'DXB'}
    if colo in premium_colos:
        colo_score = 100
    elif colo in good_colos:
        colo_score = 70
    else:
        colo_score = 40

    # 443 端口不可用扣分
    port_penalty = 0 if port_443_ok else 15

    # 加权求和
    total = (lat_score * 0.25 +
             stab_score * 0.15 +
             speed_score * 0.30 +
             route_score * 0.20 +
             colo_score * 0.10)
    total = max(0, min(100, total - port_penalty))

    breakdown = {
        'latency': round(lat_score, 1),
        'stability': round(stab_score, 1),
        'speed': round(speed_score, 1),
        'route': round(route_score, 1),
        'colo': round(colo_score, 1),
        'total': round(total, 1),
        'port_penalty': port_penalty,
    }
    return round(total, 1), breakdown


def determine_route_quality(tri_net):
    """
    根据三网路由分析结果确定整体路由质量等级

    返回: ('premium'/'good'/'normal'/'unknown', description)
    """
    detected = []
    premium_count = 0
    for isp in ('telecom', 'unicom', 'mobile'):
        info = tri_net.get(isp, {})
        if info.get('detected'):
            detected.append(info.get('line', ''))
            if info.get('premium'):
                premium_count += 1

    if not detected:
        return ('unknown', '未检测到三网骨干')

    if premium_count >= 2:
        return ('premium', f'多网优质骨干({"/".join(detected)})')
    elif premium_count == 1:
        return ('good', f'单网优质({"/".join(detected)})')
    else:
        return ('normal', f'普通骨干({"/".join(detected)})')


def parse_iptest_speed_results(raw_csv_path):
    """
    解析 iptest_raw.csv, 提取每个 IP 的下载速度

    返回: dict {ip: {'speed_mb': float, 'latency_ms': int, 'asn': str, 'isp': str}}
    """
    import csv
    results = {}

    if not os.path.exists(raw_csv_path):
        return results

    # iptest.exe 在 Windows 上输出 GBK 编码, 尝试多种编码
    content = None
    for enc in ('utf-8-sig', 'utf-8', 'gbk', 'gb2312', 'gb18030', 'latin-1'):
        try:
            with open(raw_csv_path, 'r', encoding=enc) as f:
                content = f.read()
            break
        except (UnicodeDecodeError, UnicodeError):
            continue
    if content is None:
        print(f'{C.YELLOW}[iptest解析] 无法解码文件, 所有编码均失败{C.RESET}')
        return results

    try:
        reader = csv.reader(io.StringIO(content))
        header = next(reader, None)
        for row in reader:
                if not row or len(row) < 13:
                    continue
                ip = (row[0] or '').strip()
                if not ip:
                    continue
                speed_raw = (row[12] or '').strip()
                latency_raw = (row[11] or '').strip()
                asn_num = (row[17] or '').strip() if len(row) > 17 else ''
                asn_org = (row[18] or '').strip() if len(row) > 18 else ''

                speed_mb = parse_iptest_speed(speed_raw)
                latency_ms = 0
                m = re.search(r'(\d+)', latency_raw)
                if m:
                    latency_ms = int(m.group(1))

                results[ip] = {
                    'speed_mb': speed_mb,
                    'latency_ms': latency_ms,
                    'asn': asn_num,
                    'isp': asn_org,
                }
    except Exception as e:
        print(f'{C.YELLOW}[iptest解析] 读取失败: {e}{C.RESET}')

    return results


# ============================================================
# 核心扫描逻辑
# ============================================================

def scan_range(cidr, threads=50, ports=None, top_n=10, do_trace=True, sample=None, ping_count=3, silent=False):
    """
    扫描整个 CIDR 网段

    参数:
        cidr:       CIDR 字符串, 如 '172.64.229.0/22'
        threads:    并行线程数
        ports:      TCP 端口列表
        top_n:      traceroute 的 IP 数量 (按 RTT 排序)
        do_trace:   是否执行 traceroute
        sample:     抽样数量 (None = 全量)
        ping_count: 每个 IP 的 ping 次数

    返回: (results, summary, scan_info)
    """
    if ports is None:
        ports = CF_PORTS_DEFAULT

    start_time = time.time()

    # 解析 CIDR
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        print(f'{C.RED}错误: 无效的 CIDR 格式: {cidr} ({e}){C.RESET}')
        return [], {}, {}

    all_ips = [str(ip) for ip in network]
    total_ips = len(all_ips)

    if sample and sample < total_ips:
        import random
        random.seed(42)
        all_ips = sorted(random.sample(all_ips, sample))
        total_ips = len(all_ips)

    print(f'  {C.CYAN}目标网段:{C.RESET} {cidr}  ({total_ips} 个 IP)')
    if not silent:
        print(f'  {C.CYAN}检测端口:{C.RESET} {ports}')
        print(f'  {C.CYAN}并行线程:{C.RESET} {threads}')
        print(f'  {C.CYAN}路由追踪:{C.RESET} {"是 (Top " + str(top_n) + ")" if do_trace else "否"}')
        if sample:
            print(f'  {C.YELLOW}抽样模式:{C.RESET} 随机抽取 {sample} 个 IP')
    print()

    # ---- Phase 1: ICMP RTT 检测 ----
    if not silent:
        print(f'{C.BOLD}{C.BLUE}━━━ Phase 1: 快速 ICMP RTT 检测 ━━━{C.RESET}')

    icmp_results = {}  # ip -> (avg, min, max, loss)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(ping_rtt, ip, 1.0, ping_count): ip for ip in all_ips}
        done = 0
        for future in as_completed(futures):
            ip = futures[future]
            try:
                result = future.result()
                icmp_results[ip] = result
            except Exception:
                icmp_results[ip] = (None, None, None, 100.0)
            done += 1
            progress_bar(done, total_ips, 'ICMP Ping')

    responsive_ips = [ip for ip, r in icmp_results.items() if r[0] is not None]
    unresponsive_ips = [ip for ip, r in icmp_results.items() if r[0] is None]

    if responsive_ips:
        avg_rtts = [icmp_results[ip][0] for ip in responsive_ips]
        overall_avg = sum(avg_rtts) / len(avg_rtts)
        min_rtt = min(avg_rtts)
        max_rtt = max(avg_rtts)
        print(f'  {C.GREEN}响应: {len(responsive_ips)}{C.RESET} / {total_ips}  '
              f'平均: {overall_avg:.1f}ms  最低: {min_rtt:.1f}ms  最高: {max_rtt:.1f}ms')
    else:
        print(f'  {C.RED}无响应 IP! 请检查网络连接。{C.RESET}')
    print()

    if not responsive_ips:
        return [], {}, {'cidr': cidr, 'total': total_ips, 'responsive': 0}

    # 按 RTT 排序
    responsive_ips.sort(key=lambda ip: icmp_results[ip][0] if icmp_results[ip][0] else 9999)

    # ---- Phase 2: Cloudflare 落地检测 ----
    if not silent:
        print(f'{C.BOLD}{C.BLUE}━━━ Phase 2: Cloudflare 数据中心落地检测 ━━━{C.RESET}')

    trace_results = {}  # ip -> trace dict or None

    with ThreadPoolExecutor(max_workers=min(threads, 30)) as executor:
        futures = {executor.submit(get_cf_trace, ip, 3.0): ip for ip in responsive_ips}
        done = 0
        for future in as_completed(futures):
            ip = futures[future]
            try:
                trace_results[ip] = future.result()
            except Exception:
                trace_results[ip] = None
            done += 1
            progress_bar(done, len(responsive_ips), 'CF Colo  ')

    colo_count = sum(1 for t in trace_results.values() if t and 'colo' in t)
    print(f'  {C.GREEN}检测到 colo: {colo_count}{C.RESET} / {len(responsive_ips)}')

    # 统计 colo 分布
    colo_dist = defaultdict(int)
    for trace in trace_results.values():
        if trace and 'colo' in trace:
            colo_dist[trace['colo']] += 1
    if colo_dist:
        print(f'  {C.CYAN}落地分布:{C.RESET}')
        for colo, count in sorted(colo_dist.items(), key=lambda x: -x[1]):
            city_cn = CF_COLO_MAP.get(colo, ('?', '?', colo))[2]
            print(f'    {colo:>4} ({city_cn}): {count} 个 IP')
    print()

    # ---- Phase 3: 多端口 TCP RTT 检测 (增强: 443端口多轮+IQR, 其他端口单轮) ----
    if not silent:
        print(f'{C.BOLD}{C.BLUE}━━━ Phase 3: 多端口 TCP RTT 检测 (443端口4轮+IQR) ━━━{C.RESET}')

    tcp_results = {}        # ip -> {port: rtt or None}  (单轮, 所有端口)
    tcp_stability = {}      # ip -> {median, min, jitter, valid_count, raw}  (443端口多轮)

    # 非关键端口: 单轮测试 (仅检查可达性)
    non_key_ports = [p for p in ports if p != 443]
    key_port = 443 if 443 in ports else ports[0] if ports else None

    if non_key_ports:
        tcp_tasks = [(ip, port) for ip in responsive_ips for port in non_key_ports]
        total_tcp = len(tcp_tasks)
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(tcp_rtt, ip, port, 2.0): (ip, port) for ip, port in tcp_tasks}
            done = 0
            for future in as_completed(futures):
                ip, port = futures[future]
                try:
                    rtt = future.result()
                except Exception:
                    rtt = None
                if ip not in tcp_results:
                    tcp_results[ip] = {}
                tcp_results[ip][port] = rtt
                done += 1
                progress_bar(done, total_tcp, 'TCP 其他端口')

    # 关键端口 (443): 4 轮多轮测试 + IQR 异常值过滤
    if key_port is not None:
        with ThreadPoolExecutor(max_workers=min(threads, 50)) as executor:
            futures = {executor.submit(tcp_rtt_multi_round, ip, key_port, 4, 2.0): ip for ip in responsive_ips}
            done = 0
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    median_rtt, min_rtt, jitter, valid_count, raw_rtts = future.result()
                except Exception:
                    median_rtt, min_rtt, jitter, valid_count, raw_rtts = None, None, None, 0, []
                if ip not in tcp_results:
                    tcp_results[ip] = {}
                tcp_results[ip][key_port] = median_rtt  # 用中位数代替单轮值
                tcp_stability[ip] = {
                    'median': round(median_rtt, 1) if median_rtt else None,
                    'min': round(min_rtt, 1) if min_rtt else None,
                    'jitter': round(jitter, 1) if jitter is not None else None,
                    'valid_count': valid_count,
                    'raw': [round(r, 1) for r in raw_rtts],
                }
                done += 1
                progress_bar(done, len(responsive_ips), 'TCP 443 4轮 ')

    # 统计 TCP 可用性
    tcp_ok = sum(1 for ip in responsive_ips
                 if any(v is not None for v in tcp_results.get(ip, {}).values()))
    # 443 端口稳定性统计
    stable_443 = sum(1 for ip in responsive_ips
                     if tcp_stability.get(ip, {}).get('jitter') is not None
                     and tcp_stability[ip]['jitter'] < 15)
    print(f'  {C.GREEN}TCP 可达: {tcp_ok}{C.RESET} / {len(responsive_ips)}')
    if stable_443:
        print(f'  {C.CYAN}443端口稳定(jitter<15ms): {stable_443}{C.RESET} / {len(responsive_ips)}')
    print()

    # ---- Phase 4: 路由追踪 (Top N, 并行) ----
    trace_route_results = {}  # ip -> hops list

    if do_trace and top_n > 0:
        if not silent:
            print(f'{C.BOLD}{C.BLUE}━━━ Phase 4: 路由追踪 (Top {top_n} by RTT) ━━━{C.RESET}')

        trace_ips = responsive_ips[:top_n]

        # Windows tracert 在 Python 子进程中耗时长 (单 IP ~80-100s), 适度提高并发
        with ThreadPoolExecutor(max_workers=min(top_n, 10)) as executor:
            futures = {executor.submit(run_traceroute, ip, 12, 2): ip for ip in trace_ips}
            done = 0
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    hops = future.result()
                except Exception:
                    hops = None
                trace_route_results[ip] = hops
                done += 1
                hop_count = len(hops) if hops else 0
                diag = _tracert_errors.get(ip)
                if hop_count == 0:
                    suffix = f' (traceroute 失败: {diag})' if diag else ' (traceroute 无数据)'
                    print(f'  {C.CYAN}{ip:<18}{C.RESET} hops: 0{suffix}')
                elif hops and any(h[1] == 'unreachable' for h in hops):
                    print(f'  {C.CYAN}{ip:<18}{C.RESET} hops: {hop_count} (目标不可达)')
                else:
                    print(f'  {C.CYAN}{ip:<18}{C.RESET} hops: {hop_count}')

        print()

    # ---- 综合分析 ----
    print(f'{C.BOLD}{C.BLUE}━━━ 综合分析 ━━━{C.RESET}')

    # 下载速度不再在此处从旧 iptest_raw.csv 读取 (历史上会把上一轮陈旧速度带入本轮报告)。
    # 真实速度由 main() 在 iptest 实测后统一回填到 download_speed_mb (见 backfill 逻辑)。
    speed_data = {}

    results = []
    for ip in responsive_ips:
        icmp_avg, icmp_min, icmp_max, icmp_loss = icmp_results[ip]
        trace = trace_results.get(ip)
        colo = trace.get('colo', '') if trace else ''
        loc = trace.get('loc', '') if trace else ''

        tcp_rtts = tcp_results.get(ip, {})
        valid_tcp = {p: v for p, v in tcp_rtts.items() if v is not None}
        tcp_avg = sum(valid_tcp.values()) / len(valid_tcp) if valid_tcp else None

        # 多轮 TCP 稳定性数据 (443端口)
        stab = tcp_stability.get(ip, {})
        tcp_median = stab.get('median')
        tcp_jitter = stab.get('jitter')
        tcp_stab_valid = stab.get('valid_count', 0)
        tcp_raw_rtts = stab.get('raw', [])

        # 落地城市
        colo_info = CF_COLO_MAP.get(colo, ('Unknown', loc or '??', colo or '未知'))
        city_en, country_code, city_cn = colo_info

        # 路由跳数
        hops = trace_route_results.get(ip)
        hop_count = len(hops) if hops else None

        # 路由跳数分析: 落地城市推断 + 三网骨干识别 (增强版: backtrace + GeoLite2)
        route_info = analyze_route_hops(hops)
        tri_net = route_info['tri_net']
        route_asn_path = route_info.get('route_asn_path', [])

        # 三网评分 (结合实测骨干)
        three_net = score_three_network(colo, icmp_avg, tcp_avg, tri_net)

        # 线路评级
        quality_level, quality_score, quality_desc = classify_route(
            icmp_avg, tcp_rtts, colo, hop_count
        )

        # CF 优选判断
        cf_opt, cf_opt_desc = check_cf_optimization(quality_level, quality_score, tcp_rtts, colo)

        # 稀有优质段
        is_rare, rare_desc = check_rare_premium(
            quality_level, quality_score, icmp_avg, tcp_rtts, colo
        )

        # 路由质量等级 (基于实测 ASN)
        route_quality, route_quality_desc = determine_route_quality(tri_net)

        # 下载速度 (来自 iptest)
        speed_info = speed_data.get(ip, {})
        download_speed = speed_info.get('speed_mb', 0.0) if speed_info else None

        # 加权综合评分
        port_443_ok = tcp_rtts.get(443) is not None
        comp_score, comp_breakdown = composite_score(
            icmp_avg, tcp_median, tcp_jitter, download_speed,
            route_quality, colo, port_443_ok
        )

        results.append({
            'ip': ip,
            'icmp_rtt': round(icmp_avg, 1) if icmp_avg else None,
            'icmp_min': round(icmp_min, 1) if icmp_min else None,
            'icmp_max': round(icmp_max, 1) if icmp_max else None,
            'icmp_loss': icmp_loss,
            'cf_colo': colo,
            'landing_city': city_cn,
            'landing_city_en': city_en,
            'landing_country': country_code,
            'tcp_rtts': {str(p): round(v, 1) if v else None for p, v in tcp_rtts.items()},
            'tcp_avg_rtt': round(tcp_avg, 1) if tcp_avg else None,
            'tcp_median_rtt': tcp_median,       # 443端口中位数 RTT
            'tcp_jitter': tcp_jitter,            # 443端口抖动
            'tcp_stab_valid': tcp_stab_valid,    # 443端口有效轮数
            'tcp_raw_rtts': tcp_raw_rtts,        # 443端口原始RTT列表
            'tcp_ports_ok': len(valid_tcp),
            'tcp_ports_total': len(ports),
            'hop_count': hop_count,
            'traceroute': [{'hop': h[0], 'ip': h[1], 'host': h[2], 'rtt': h[3]} for h in hops] if hops else None,
            'route_landing': route_info['route_landing'],
            'route_landing_code': route_info['route_landing_code'],
            'route_landing_evidence': route_info['route_landing_evidence'],
            'route_asn_path': route_asn_path,     # ASN 路径详情
            'route_quality': route_quality,        # 路由质量等级
            'route_quality_desc': route_quality_desc,
            'tri_net': tri_net,
            'three_net': {
                'unicom':  three_net['unicom']['score'],
                'telecom': three_net['telecom']['score'],
                'mobile':  three_net['mobile']['score'],
            },
            'quality_level': quality_level,
            'quality_score': quality_score,
            'quality_desc': quality_desc,
            'download_speed_mb': round(download_speed, 1) if download_speed else None,
            'composite_score': comp_score,         # 加权综合评分
            'composite_breakdown': comp_breakdown, # 评分明细
            'cf_optimization': cf_opt,
            'cf_opt_desc': cf_opt_desc,
            'rare_premium': is_rare,
            'rare_desc': rare_desc,
        })

    # 按综合评分排序 (有下载速度时按综合评分, 否则按 RTT)
    has_speed = any(r.get('download_speed_mb') for r in results)
    if has_speed:
        results.sort(key=lambda x: (x.get('composite_score') or 0), reverse=True)
        sort_key = '综合评分'
    else:
        results.sort(key=lambda x: (x['icmp_rtt'] if x['icmp_rtt'] else 9999))
        sort_key = 'ICMP RTT'
    print(f'  {C.CYAN}排序方式: {sort_key}{C.RESET}')

    # 汇总统计
    summary = {
        'total_ips': total_ips,
        'responsive': len(responsive_ips),
        'unresponsive': len(unresponsive_ips),
        'colo_distribution': dict(colo_dist),
        'quality_distribution': {
            'premium': sum(1 for r in results if r['quality_level'] == 'premium'),
            'good':    sum(1 for r in results if r['quality_level'] == 'good'),
            'normal':  sum(1 for r in results if r['quality_level'] == 'normal'),
            'poor':    sum(1 for r in results if r['quality_level'] == 'poor'),
        },
        'cf_optimization_count': sum(1 for r in results if r['cf_optimization']),
        'rare_premium_count':    sum(1 for r in results if r['rare_premium']),
        'tri_net_counts': {
            'telecom': sum(1 for r in results if r.get('tri_net', {}).get('telecom', {}).get('detected')),
            'unicom':  sum(1 for r in results if r.get('tri_net', {}).get('unicom', {}).get('detected')),
            'mobile':  sum(1 for r in results if r.get('tri_net', {}).get('mobile', {}).get('detected')),
        },
        'tri_net_premium_counts': {
            'telecom': sum(1 for r in results if r.get('tri_net', {}).get('telecom', {}).get('premium')),
            'unicom':  sum(1 for r in results if r.get('tri_net', {}).get('unicom', {}).get('premium')),
            'mobile':  sum(1 for r in results if r.get('tri_net', {}).get('mobile', {}).get('premium')),
        },
        'avg_rtt': round(sum(r['icmp_rtt'] for r in results if r['icmp_rtt']) / max(1, len([r for r in results if r['icmp_rtt']])), 1),
        'min_rtt': min((r['icmp_rtt'] for r in results if r['icmp_rtt']), default=None),
        'avg_composite_score': round(sum(r.get('composite_score', 0) for r in results) / max(1, len(results)), 1) if results else 0,
        'max_composite_score': max((r.get('composite_score', 0) for r in results), default=0),
        'has_speed_data': has_speed,
        'stable_443_count': sum(1 for r in results if r.get('tcp_jitter') is not None and r['tcp_jitter'] < 15),
        'duration': round(time.time() - start_time, 1),
    }

    scan_info = {
        'cidr': cidr,
        'total': total_ips,
        'responsive': len(responsive_ips),
        'ports': ports,
        'threads': threads,
        'sample': sample,
        'scan_time': now_str(),
        'duration': summary['duration'],
    }

    return results, summary, scan_info


# ============================================================
# 报告输出
# ============================================================

def print_console_report(results, summary, scan_info, local_isp=None, top_display=30):
    """打印控制台报告"""

    print(f'\n{C.BOLD}{C.MAGENTA}{"=" * 78}{C.RESET}')
    print(f'{C.BOLD}{C.MAGENTA}  检测结果汇总{C.RESET}')
    print(f'{C.BOLD}{C.MAGENTA}{"=" * 78}{C.RESET}\n')

    if local_isp:
        print(f'  {C.CYAN}本地 ISP:{C.RESET}   {local_isp.get("isp_cn", "未知")} ({local_isp.get("isp", "")})')
        print(f'  {C.CYAN}本地 IP:{C.RESET}   {local_isp.get("ip", "未知")}')
        print(f'  {C.CYAN}所在城市:{C.RESET}   {local_isp.get("city", "未知")}')
        print()

    print(f'  {C.CYAN}网段:{C.RESET}     {scan_info["cidr"]}')
    print(f'  {C.CYAN}总 IP 数:{C.RESET}  {summary["total_ips"]}')
    print(f'  {C.CYAN}响应数:{C.RESET}   {summary["responsive"]}')
    print(f'  {C.CYAN}平均 RTT:{C.RESET} {summary["avg_rtt"]}ms')
    print(f'  {C.CYAN}最低 RTT:{C.RESET} {summary["min_rtt"]}ms')
    if summary.get('has_speed_data'):
        print(f'  {C.CYAN}平均综合评分:{C.RESET} {summary.get("avg_composite_score", 0)}/100')
        print(f'  {C.CYAN}最高综合评分:{C.RESET} {summary.get("max_composite_score", 0)}/100')
    if summary.get('stable_443_count'):
        print(f'  {C.CYAN}443稳定(jitter<15ms):{C.RESET} {summary["stable_443_count"]} 个')
    print(f'  {C.CYAN}耗时:{C.RESET}     {summary["duration"]}秒')
    print()

    # 质量分布
    qd = summary['quality_distribution']
    print(f'  {C.BOLD}线路质量分布:{C.RESET}')
    print(f'    {C.GREEN}优质 (Premium): {qd["premium"]}{C.RESET}')
    print(f'    {C.CYAN}良好 (Good):    {qd["good"]}{C.RESET}')
    print(f'    {C.YELLOW}普通 (Normal):  {qd["normal"]}{C.RESET}')
    print(f'    {C.RED}较差 (Poor):    {qd["poor"]}{C.RESET}')
    print()

    print(f'  {C.GREEN}适合 CF 优选: {summary["cf_optimization_count"]}{C.RESET} 个 IP')
    print(f'  {C.MAGENTA}稀有优质段:   {summary["rare_premium_count"]}{C.RESET} 个 IP')
    tnc = summary.get('tri_net_counts', {})
    tnp = summary.get('tri_net_premium_counts', {})
    if any(tnc.values()):
        print(f'  {C.BOLD}三网骨干命中:{C.RESET}'
              f'  电信 {tnc.get("telecom",0)}(优{tnp.get("telecom",0)}) / '
              f'联通 {tnc.get("unicom",0)}(优{tnp.get("unicom",0)}) / '
              f'移动 {tnc.get("mobile",0)}(优{tnp.get("mobile",0)})')
    print()

    # Top N 详细列表 (增强: 显示综合评分/jitter/下载速度)
    display_count = min(top_display, len(results))
    if summary.get('has_speed_data'):
        print(f'{C.BOLD}  {"IP地址":<18} {"ICMP":>7} {"Colo":>5} {"城市":<10} '
              f'{"Jitter":>7} {"速度MB/s":>8} {"综合":>5} {"质量":>4} {"优选":>3}{C.RESET}')
    else:
        print(f'{C.BOLD}  {"IP地址":<18} {"ICMP":>7} {"Colo":>5} {"城市":<10} '
              f'{"Jitter":>7} {"联通":>4} {"电信":>4} {"移动":>4} '
              f'{"质量":>4} {"优选":>3}{C.RESET}')
    print(f'  {"-" * 95}')

    for r in results[:display_count]:
        ip_str = r['ip']
        icmp_str = rtt_color(r['icmp_rtt'])
        colo = r['cf_colo'] or '?'
        city = r['landing_city'][:8] if r['landing_city'] else '?'

        # Jitter 显示
        jit = r.get('tcp_jitter')
        if jit is not None:
            if jit < 5:
                jit_str = f'{C.GREEN}{jit:>5.1f}ms{C.RESET}'
            elif jit < 15:
                jit_str = f'{C.CYAN}{jit:>5.1f}ms{C.RESET}'
            elif jit < 30:
                jit_str = f'{C.YELLOW}{jit:>5.1f}ms{C.RESET}'
            else:
                jit_str = f'{C.RED}{jit:>5.1f}ms{C.RESET}'
        else:
            jit_str = f'{C.DIM}  N/A{C.RESET}'

        q = r['quality_level']
        if q == 'premium':
            q_str = f'{C.GREEN}优质{C.RESET}'
        elif q == 'good':
            q_str = f'{C.CYAN}良好{C.RESET}'
        elif q == 'normal':
            q_str = f'{C.YELLOW}普通{C.RESET}'
        else:
            q_str = f'{C.RED}较差{C.RESET}'

        opt_str = f'{C.GREEN}✓{C.RESET}' if r['cf_optimization'] else f'{C.RED}✗{C.RESET}'

        if summary.get('has_speed_data'):
            speed = r.get('download_speed_mb')
            if speed and speed > 0:
                if speed >= 20:
                    spd_str = f'{C.GREEN}{speed:>7.1f}{C.RESET}'
                elif speed >= 10:
                    spd_str = f'{C.CYAN}{speed:>7.1f}{C.RESET}'
                else:
                    spd_str = f'{C.YELLOW}{speed:>7.1f}{C.RESET}'
            else:
                spd_str = f'{C.DIM}    0.0{C.RESET}'
            comp = r.get('composite_score', 0)
            if comp >= 75:
                comp_str = f'{C.GREEN}{comp:>4.0f}{C.RESET}'
            elif comp >= 50:
                comp_str = f'{C.CYAN}{comp:>4.0f}{C.RESET}'
            else:
                comp_str = f'{C.YELLOW}{comp:>4.0f}{C.RESET}'
            print(f'  {ip_str:<18} {icmp_str:>7} {colo:>5} {city:<10} '
                  f'{jit_str:>7} {spd_str:>8} {comp_str:>5} {q_str:>4} {opt_str:>3}')
        else:
            tn = r['three_net']
            print(f'  {ip_str:<18} {icmp_str:>7} {colo:>5} {city:<10} '
                  f'{jit_str:>7} {tn["unicom"]:>3}★ {tn["telecom"]:>3}★ {tn["mobile"]:>3}★ '
                  f'{q_str:>4} {opt_str:>3}')

    # 路由落地 & 三网骨干交叉核对 (增强: 显示 ASN 线路标签)
    traced = [r for r in results[:display_count]
              if r.get('route_landing') or
              any(r.get('tri_net', {}).get(n, {}).get('detected') for n in ('telecom', 'unicom', 'mobile'))]
    if traced:
        print()
        print(f'{C.BOLD}{C.BLUE}  路由落地 & 三网骨干 (backtrace + GeoLite2 ASN):{C.RESET}')
        for r in traced:
            tn = r.get('tri_net', {})
            parts = []
            if r.get('route_landing'):
                parts.append(f'{C.CYAN}路由落地={r["route_landing"]}{C.RESET}')
            for net, key, col in (('telecom', '电信', C.YELLOW), ('unicom', '联通', C.GREEN), ('mobile', '移动', C.MAGENTA)):
                info = tn.get(net, {})
                if info.get('detected'):
                    label = (info.get('label') or '').strip()
                    conf = info.get('confidence', '')
                    conf_txt = ' [已确认]' if conf == 'confirmed' else (' [混合]' if conf == 'mixed' else '')
                    parts.append(f'{col}{key}: {label}{conf_txt} ({info.get("evidence","")}){C.RESET}')
            # 显示 ASN 路径
            asn_path = r.get('route_asn_path', [])
            if asn_path:
                path_summary = ' → '.join(f'{h["asn"]}/{h["line"]}' for h in asn_path[:5])
                parts.append(f'{C.DIM}ASN路径: {path_summary}{C.RESET}')
            if parts:
                print(f'    {r["ip"]:<18} ' + '  '.join(parts))

    if len(results) > display_count:
        print(f'\n  {C.DIM}... 还有 {len(results) - display_count} 个 IP (详见报告文件){C.RESET}')

    print()

    # 稀有优质段详情
    rare_ips = [r for r in results if r['rare_premium']]
    if rare_ips:
        print(f'{C.BOLD}{C.MAGENTA}  ★ 稀有优质段详情:{C.RESET}')
        for r in rare_ips:
            print(f'    {C.MAGENTA}{r["ip"]:<18}{C.RESET} {r["rare_desc"]}')
        print()

    # CF 优选推荐 Top 10 (增强: 显示综合评分/jitter/速度)
    opt_ips = [r for r in results if r['cf_optimization']][:10]
    if opt_ips:
        print(f'{C.BOLD}{C.GREEN}  ✓ Cloudflare 优选推荐 Top 10:{C.RESET}')
        for i, r in enumerate(opt_ips, 1):
            comp = r.get('composite_score', 0)
            jit = r.get('tcp_jitter')
            speed = r.get('download_speed_mb')
            jit_s = f' jitter={jit:.0f}ms' if jit is not None else ''
            spd_s = f' 速度={speed:.1f}MB/s' if speed else ''
            comp_s = f' 评分={comp:.0f}' if comp else ''
            print(f'    {i:>2}. {C.GREEN}{r["ip"]:<18}{C.RESET} '
                  f'RTT={r["icmp_rtt"]}ms  {r["cf_colo"]}({r["landing_city"]})'
                  f'{comp_s}{jit_s}{spd_s}  {r["cf_opt_desc"]}')
        print()

    # 按运营商分别推荐最优 IP (新增)
    print(f'{C.BOLD}{C.CYAN}  >> 按运营商分别推荐最优 IP:{C.RESET}')
    isp_labels = {'telecom': '电信', 'unicom': '联通', 'mobile': '移动'}
    isp_colors = {'telecom': C.YELLOW, 'unicom': C.GREEN, 'mobile': C.MAGENTA}
    for net in ('telecom', 'unicom', 'mobile'):
        # 该运营商优质骨干命中的 IP, 按综合评分排序
        isp_ips = [r for r in results
                   if r.get('tri_net', {}).get(net, {}).get('detected')
                   and r.get('cf_optimization')]
        if not isp_ips:
            # 回退: 所有优选 IP
            isp_ips = [r for r in results if r.get('cf_optimization')]
        if isp_ips:
            isp_ips.sort(key=lambda x: x.get('composite_score', 0), reverse=True)
            best = isp_ips[0]
            info = best.get('tri_net', {}).get(net, {})
            line_tag = info.get('line', '')
            asn_tag = info.get('asn', '')
            premium_tag = ' [优质]' if info.get('premium') else ''
            comp = best.get('composite_score', 0)
            speed = best.get('download_speed_mb')
            spd_s = f' 速度={speed:.1f}MB/s' if speed else ''
            print(f'    {isp_colors[net]}{isp_labels[net]}:{C.RESET} {C.GREEN}{best["ip"]:<18}{C.RESET} '
                  f'RTT={best["icmp_rtt"]}ms  {best["cf_colo"]}({best["landing_city"]})  '
                  f'线路={line_tag}/{asn_tag}{premium_tag}  评分={comp:.0f}{spd_s}')
        else:
            print(f'    {isp_colors[net]}{isp_labels[net]}:{C.RESET} 无可用优选 IP')
    print()


def save_json_report(results, summary, scan_info, local_isp, filename):
    """保存 JSON 报告"""
    report = {
        'scan_info': scan_info,
        'local_isp': local_isp,
        'summary': summary,
        'results': results,
    }
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f'  {C.GREEN}JSON 报告已保存:{C.RESET} {filename}')


def save_text_report(results, summary, scan_info, local_isp, filename):
    """保存文本报告"""
    lines = []
    lines.append('=' * 78)
    lines.append('  Cloudflare CDN IP 三网检测报告')
    lines.append('=' * 78)
    lines.append('')

    if local_isp:
        lines.append(f'  本地 ISP:   {local_isp.get("isp_cn", "未知")} ({local_isp.get("isp", "")})')
        lines.append(f'  本地 IP:   {local_isp.get("ip", "未知")}')
        lines.append(f'  所在城市:   {local_isp.get("city", "未知")}')
        lines.append('')

    lines.append(f'  网段:       {scan_info["cidr"]}')
    lines.append(f'  检测时间:   {scan_info["scan_time"]}')
    lines.append(f'  总 IP 数:   {summary["total_ips"]}')
    lines.append(f'  响应数:     {summary["responsive"]}')
    lines.append(f'  平均 RTT:   {summary["avg_rtt"]}ms')
    lines.append(f'  最低 RTT:   {summary["min_rtt"]}ms')
    lines.append(f'  耗时:       {summary["duration"]}秒')
    lines.append('')

    # 质量分布
    qd = summary['quality_distribution']
    lines.append('  线路质量分布:')
    lines.append(f'    优质 (Premium): {qd["premium"]}')
    lines.append(f'    良好 (Good):    {qd["good"]}')
    lines.append(f'    普通 (Normal):  {qd["normal"]}')
    lines.append(f'    较差 (Poor):    {qd["poor"]}')
    lines.append('')

    lines.append(f'  适合 CF 优选: {summary["cf_optimization_count"]} 个 IP')
    lines.append(f'  稀有优质段:   {summary["rare_premium_count"]} 个 IP')
    tnc = summary.get('tri_net_counts', {})
    if any(tnc.values()):
        lines.append(f'  三网骨干命中 (traceroute 跳数):  电信 {tnc.get("telecom",0)} 个 / '
                    f'联通 {tnc.get("unicom",0)} 个 / 移动 {tnc.get("mobile",0)} 个')
    lines.append('')

    # Colos 分布
    if summary['colo_distribution']:
        lines.append('  落地数据中心分布:')
        for colo, count in sorted(summary['colo_distribution'].items(), key=lambda x: -x[1]):
            city_cn = CF_COLO_MAP.get(colo, ('?', '?', colo))[2]
            lines.append(f'    {colo:>4} ({city_cn}): {count} 个 IP')
        lines.append('')

    # 详细列表
    lines.append('-' * 78)
    lines.append(f'  {"IP地址":<18} {"ICMP":>8} {"Colo":>5} {"落地城市":<14} '
                 f'{"路由落地":<14} {"联通":>4} {"电信":>4} {"移动":>4} '
                 f'{"质量":>4} {"优选":>4} {"稀有":>4}')
    lines.append('-' * 78)

    for r in results:
        q_map = {'premium': '优质', 'good': '良好', 'normal': '普通', 'poor': '较差'}
        tn = r['three_net']
        rl = r['route_landing'] or '-'
        lines.append(
            f'  {r["ip"]:<18} '
            f'{str(r["icmp_rtt"] or "超时"):>8} '
            f'{r["cf_colo"] or "?":>5} '
            f'{r["landing_city"][:12]:<14} '
            f'{rl[:12]:<14} '
            f'{tn["unicom"]:>3}★ {tn["telecom"]:>3}★ {tn["mobile"]:>3}★ '
            f'{q_map[r["quality_level"]]:>4} '
            f'{"✓" if r["cf_optimization"] else "✗":>4} '
            f'{"★" if r["rare_premium"] else "":>4}'
        )

    lines.append('')

    # 路由落地 & 三网骨干详情 (仅列出有路由分析/骨干命中的 IP)
    traced = [r for r in results
              if r.get('route_landing') or
              any(r.get('tri_net', {}).get(n, {}).get('detected') for n in ('telecom', 'unicom', 'mobile'))]
    if traced:
        lines.append('-' * 78)
        lines.append('  路由落地 & 三网骨干 (来自 traceroute 跳数分析):')
        for r in traced:
            tn = r.get('tri_net', {})
            parts = []
            if r.get('route_landing'):
                parts.append(f'路由落地={r["route_landing"]} ({r.get("route_landing_evidence","")})')
            for net, key in (('telecom', '电信'), ('unicom', '联通'), ('mobile', '移动')):
                info = tn.get(net, {})
                if info.get('detected'):
                    label = (info.get('label') or '').strip()
                    conf = info.get('confidence', '')
                    conf_txt = ' [已确认]' if conf == 'confirmed' else (' [混合]' if conf == 'mixed' else '')
                    parts.append(f'{key}: {label}{conf_txt} ({info.get("evidence","")})')
            if parts:
                lines.append(f'    {r["ip"]:<18} ' + ' | '.join(parts))
        lines.append('')

    # 稀有优质段
    rare_ips = [r for r in results if r['rare_premium']]
    if rare_ips:
        lines.append('-' * 78)
        lines.append('  ★ 稀有优质段详情:')
        for r in rare_ips:
            lines.append(f'    {r["ip"]:<18} {r["rare_desc"]}')
        lines.append('')

    # CF 优选推荐
    opt_ips = [r for r in results if r['cf_optimization']][:20]
    if opt_ips:
        lines.append('-' * 78)
        lines.append('  ✓ Cloudflare 优选推荐 Top 20:')
        for i, r in enumerate(opt_ips, 1):
            rl = f' / 路由:{r["route_landing"]}' if r.get('route_landing') else ''
            lines.append(f'    {i:>2}. {r["ip"]:<18} RTT={r["icmp_rtt"]}ms  '
                        f'{r["cf_colo"]}({r["landing_city"]}){rl}  {r["cf_opt_desc"]}')
        lines.append('')

    lines.append('=' * 78)

    with open(filename, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    print(f'  {C.GREEN}文本报告已保存:{C.RESET} {filename}')


def save_top_ips(results, filename, count=20):
    """导出优选 IP 列表 (纯 IP, 每行一个, 按综合评分排序)"""
    opt_ips = [r for r in results if r['cf_optimization']]
    opt_ips.sort(key=lambda x: (x.get('composite_score') or 0, -(x.get('icmp_rtt') or 9999)), reverse=True)
    opt_ips = opt_ips[:count]
    with open(filename, 'w', encoding='utf-8') as f:
        for r in opt_ips:
            f.write(f'{r["ip"]}\n')
    print(f'  {C.GREEN}优选 IP 列表已保存:{C.RESET} {filename} ({len(opt_ips)} 个)')


def save_csv_report(results, summary, scan_info, local_isp, filename, ports):
    """
    保存 CSV 报告 (Excel 兼容, UTF-8 BOM)

    增强版: 包含 TCP中位数/jitter/下载速度/综合评分/路由质量/ASN路径
    """
    import csv

    # 表头
    header = [
        'IP地址', 'ICMP_RTT_ms', 'ICMP_Min_ms', 'ICMP_Max_ms', 'ICMP_丢包率%',
        'CF_Colo', '落地城市', '落地国家',
        'TCP_平均RTT_ms', 'TCP_443中位数RTT_ms', 'TCP_443_Jitter_ms', 'TCP_443_有效轮数',
        'TCP_可达端口', 'TCP_总端口',
    ]
    # 各端口列
    for p in ports:
        header.append(f'TCP_{p}_RTT_ms')
    header += [
        '路由跳数',
        '路由落地(推测)', '路由落地证据',
        '路由质量等级', '路由质量描述',
        # 三网回程汇总列 (格式: 优质/命中 + [线路/ASN] + (证据IP))
        '电信回程', '联通回程', '移动回程',
        '联通评分', '电信评分', '移动评分',
        '下载速度_MB/s',
        '综合评分', '延迟评分', '稳定性评分', '速度评分', '路由评分', '落地评分',
        '质量等级', '质量分数',
        '适合CF优选', '稀有优质段',
        '优选说明', '稀有说明',
    ]

    with open(filename, 'w', encoding='utf-8-sig', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(header)

        for r in results:
            tn = r.get('tri_net', {})
            cb = r.get('composite_breakdown', {})
            row = [
                r['ip'],
                r['icmp_rtt'] if r['icmp_rtt'] is not None else '',
                r['icmp_min'] if r['icmp_min'] is not None else '',
                r['icmp_max'] if r['icmp_max'] is not None else '',
                r['icmp_loss'],
                r['cf_colo'] or '',
                r['landing_city'] or '',
                r['landing_country'] or '',
                r['tcp_avg_rtt'] if r['tcp_avg_rtt'] is not None else '',
                r.get('tcp_median_rtt') or '',
                r.get('tcp_jitter') or '',
                r.get('tcp_stab_valid') or '',
                r['tcp_ports_ok'],
                r['tcp_ports_total'],
            ]
            # 各端口 RTT
            for p in ports:
                v = r['tcp_rtts'].get(str(p))
                row.append(v if v is not None else '')
            row += [
                r['hop_count'] if r['hop_count'] is not None else '',
                r['route_landing'] or '',
                r['route_landing_evidence'] or '',
                r.get('route_quality') or '',
                r.get('route_quality_desc') or '',
                # 三网回程汇总 (格式: 优质[CN2/AS4809](59.43.x.x) 或 "-")
                _tri_net_cell(tn.get('telecom', {})),
                _tri_net_cell(tn.get('unicom', {})),
                _tri_net_cell(tn.get('mobile', {})),
                r['three_net']['unicom'],
                r['three_net']['telecom'],
                r['three_net']['mobile'],
                r.get('download_speed_mb') or '',
                r.get('composite_score') or '',
                cb.get('latency') or '',
                cb.get('stability') or '',
                cb.get('speed') or '',
                cb.get('route') or '',
                cb.get('colo') or '',
                r['quality_level'],
                r['quality_score'],
                'YES' if r['cf_optimization'] else 'NO',
                'YES' if r['rare_premium'] else 'NO',
                r['cf_opt_desc'] or '',
                r['rare_desc'] or '',
            ]
            writer.writerow(row)

    print(f'  {C.GREEN}CSV 报告已保存:{C.RESET} {filename} ({len(results)} 行)')


def _tri_net_cell(info):
    """将三网骨干命中信息格式化为 CSV 单元格文本。

    呈现 backtrace 的精确线路标签与置信度:
      - 已确认精品:  ``电信CN2GIA [精品线路] [已确认](59.43.1.1,202.97.1.1)``
      - 优质混合:    ``联通9929混合 [优质线路] [混合](218.105.1.1)``
      - 普通骨干:    ``电信163    [普通线路] [已确认](202.97.1.1)``
      - 无骨干信息:  ``-``
    """
    if not info or not info.get('detected'):
        return '-'
    label = (info.get('label') or '').strip()
    confidence = info.get('confidence', '')
    ev = info.get('evidence', '')
    if confidence == 'confirmed':
        conf_txt = ' [已确认]'
    elif confidence == 'mixed':
        conf_txt = ' [混合]'
    else:
        conf_txt = ''
    if ev:
        return f'{label}{conf_txt} ({ev})'
    return f'{label}{conf_txt}'


def save_ip_port_list(results, filename, port=443, only_optimal=True):
    """
    导出 ip.txt (格式: "IP 端口", 空格分隔)

    可直接作为 Cloudflare 优选 / Speed Test 工具的输入列表。
    默认只导出「适合CF优选」的 IP; 指定 only_optimal=False 则导出全部响应 IP。
    """
    if only_optimal:
        items = [r for r in results if r.get('cf_optimization')]
        # 按综合评分排序 (有评分时), 否则按 RTT
        items.sort(key=lambda x: (x.get('composite_score') or 0, -(x.get('icmp_rtt') or 9999)), reverse=True)
        label = 'CF优选'
    else:
        items = [r for r in results if r.get('icmp_rtt') is not None or (r.get('tcp_ports_ok') or 0) > 0]
        items.sort(key=lambda x: (x.get('icmp_rtt') or 9999))
        label = '全部响应'

    with open(filename, 'w', encoding='utf-8') as f:
        for r in items:
            f.write(f'{r["ip"]} {port}\n')

    print(f'  {C.GREEN}IP列表已保存 (ip.txt, {label}):{C.RESET} {filename} ({len(items)} 个, 端口 {port})')


def parse_iptest_speed(s):
    """解析 iptest 下载速度字段, 如 '25007 kB/s' -> 25.007 (MB/s)。返回浮点 MB/s。"""
    if not s:
        return 0.0
    m = re.search(r'(\d+(?:\.\d+)?)', s.replace(',', ''))
    if not m:
        return 0.0
    val = float(m.group(1))
    # iptest 输出单位为 kB/s, 转换为 MB/s (÷1000)
    return val / 1000.0


def filter_iptest_raw_csv(raw_csv, min_speed_mb=10.0):
    """
    按下载速度阈值过滤 iptest_raw.csv (就地覆盖)。

    保留规则:
      - 下载速度 (第 13 列, 单位 kB/s) 解析为 MB/s 后 >= min_speed_mb 的行保留
      - 测速失败 / 未测速 (速度 <= 0, 即 0 kB/s) 的行丢弃, 不作为优选结果输出
      - 真实速度但低于 min_speed_mb 的行丢弃 (不满足阈值要求)
    过滤前将原始完整数据 (含全部真实速度与 0 失败行) 备份到 iptest_raw_full.csv。

    返回: (kept, dropped) 计数; 失败时返回 (None, None)
    """
    import csv

    try:
        with open(raw_csv, 'r', encoding='utf-8-sig', newline='') as f:
            rows = list(csv.reader(f))
    except Exception as e:
        print(f'{C.RED}[iptest] 读取原始结果失败: {e}{C.RESET}')
        return None, None

    if not rows:
        return 0, 0

    header = rows[0]

    # 备份原始完整数据 (便于后续用不同阈值重新过滤, 无需重跑测速)
    full_csv = os.path.join(os.path.dirname(os.path.abspath(raw_csv)), 'iptest_raw_full.csv')
    try:
        with open(full_csv, 'w', encoding='utf-8-sig', newline='') as f:
            csv.writer(f).writerows(rows)
    except Exception:
        pass

    # 下载速度列索引 (与 parse_iptest_speed / run_iptest_speedtest 保持一致)
    speed_idx = 12

    kept, dropped = [], 0
    for i, row in enumerate(rows):
        if i == 0:                      # 表头
            kept.append(row)
            continue
        if not row or len(row) <= speed_idx:
            # 列数不足, 无法判断速度 -> 保留 (避免误删)
            kept.append(row)
            continue
        speed_raw = (row[speed_idx] or '').strip()
        speed_mb = parse_iptest_speed(speed_raw)
        if speed_mb <= 0:
            # 测速失败 / 未测速 (0 kB/s) -> 丢弃, 不作为优选结果输出
            dropped += 1
            continue
        if speed_mb >= min_speed_mb:
            kept.append(row)
        else:
            # 真实速度但低于阈值 -> 丢弃 (不满足阈值要求)
            dropped += 1

    try:
        with open(raw_csv, 'w', encoding='utf-8-sig', newline='') as f:
            csv.writer(f).writerows(kept)
    except Exception as e:
        print(f'{C.RED}[iptest] 写回过滤结果失败: {e}{C.RESET}')
        return None, None

    n_kept = len(kept) - 1  # 去掉表头
    print(f'  {C.CYAN}[iptest] 下载速度过滤 (>= {min_speed_mb:.1f} MB/s): '
          f'保留 {n_kept} 条, 过滤掉 {dropped} 条{C.RESET}')
    print(f'  {C.DIM}原始完整数据已备份: {full_csv}{C.RESET}')
    return n_kept, dropped


def run_iptest_speedtest(ip_txt_path, script_dir=None, iptest_exe=None,
                         delay=0, speedtest=5, maxc=100,
                         min_speed_mb=10.0,
                         result_file='iptest_result.txt'):
    """
    在 ip.txt 生成后调用 iptest.exe 进行优选测速, 并将结果重整为:
        IP:端口#国旗 | 城市 | ⬇️X.XMB/s | ❤️CF

    参数:
        ip_txt_path  : iptest 的输入文件 (格式 "IP 端口", 由 save_ip_port_list 生成)
        script_dir   : 工作目录 (用于定位 iptest.exe 与输出)
        iptest_exe   : iptest 可执行文件路径 (默认: script_dir/iptest.exe)
        delay        : 透传给 iptest 的延迟阈值 ms (0=禁用)
        speedtest    : 透传给 iptest 的下载测速并发数 (0=禁用)
        maxc         : 透传给 iptest 的并发协程数
        min_speed_mb : 下载速度阈值 (MB/s), 仅保留 >= 该值的 IP; <=0 表示不过滤
        result_file  : 重整后的结果输出文件路径
    """
    import csv

    script_dir = script_dir or os.path.dirname(os.path.abspath(__file__))
    if iptest_exe is None:
        iptest_exe = os.path.join(script_dir, 'iptest.exe')
    if not os.path.exists(iptest_exe):
        print(f'{C.YELLOW}[iptest] 未找到 iptest.exe: {iptest_exe}, 跳过优选测速{C.RESET}')
        return None
    if not os.path.exists(ip_txt_path):
        print(f'{C.YELLOW}[iptest] 输入文件不存在: {ip_txt_path}, 跳过{C.RESET}')
        return None

    raw_csv = os.path.join(script_dir, 'iptest_raw.csv')
    print(f'\n{C.BOLD}{C.BLUE}━━━ iptest 优选测速 ━━━{C.RESET}')
    print(f'  输入: {ip_txt_path}')
    print(f'  程序: {iptest_exe}')

    cmd = [iptest_exe, '-file', ip_txt_path, '-outfile', raw_csv,
           '-speedtest', str(speedtest), '-max', str(maxc), '-tls']
    if delay and delay > 0:
        cmd += ['-delay', str(delay)]

    try:
        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'
        proc = subprocess.run(cmd, cwd=script_dir, capture_output=True, text=True,
                              encoding='utf-8', env=env, timeout=900)
        if proc.returncode != 0 and proc.stderr:
            print(f'  {C.YELLOW}[iptest] 返回码 {proc.returncode}, stderr: {proc.stderr[:500]}{C.RESET}')
    except subprocess.TimeoutExpired:
        print(f'{C.RED}[iptest] 测速超时 (900s), 跳过{C.RESET}')
        return None
    except Exception as e:
        print(f'{C.RED}[iptest] 调用失败: {e}{C.RESET}')
        return None

    if not os.path.exists(raw_csv):
        print(f'{C.RED}[iptest] 未生成结果文件: {raw_csv}{C.RESET}')
        return None

    # 始终清理 iptest_raw.csv: 丢弃测速失败(0 kB/s)的行;
    # 若设置了正阈值 (min_speed_mb > 0) 则同时按阈值过滤。
    # 完整的原始实测数据 (含全部真实速度与 0 失败行) 始终备份到 iptest_raw_full.csv,
    # 供主报告回读真实速度, 保证报告与 iptest_result.txt 使用同一轮实测数据。
    eff_min = min_speed_mb if (min_speed_mb and min_speed_mb > 0) else 0.0
    filter_iptest_raw_csv(raw_csv, min_speed_mb=eff_min)

    # 解析 iptest 输出 CSV 并重整为统一格式
    # 表头: IP地址,端口号,TLS,数据中心,IP位置,地区,城市,地区(中文),国家,城市(中文),国旗,网络延迟,下载速度,...
    # 列索引: 0=IP, 1=端口, 6=城市(en), 9=城市(中文), 10=国旗, 12=下载速度
    lines = []
    try:
        with open(raw_csv, 'r', encoding='utf-8-sig', newline='') as f:
            reader = csv.reader(f)
            header = next(reader, None)
            for row in reader:
                if not row or len(row) < 13:
                    continue
                ip = (row[0] or '').strip()
                port = (row[1] or '').strip()
                flag = (row[10] or '').strip()       # 国旗
                city_cn = (row[9] or '').strip()      # 城市(中文)
                city_en = (row[6] or '').strip()      # 城市(en)
                speed_raw = (row[12] or '').strip()   # 下载速度 (如 "25007 kB/s")
                if not ip:
                    continue
                city = city_cn or city_en or ''
                speed_mb = parse_iptest_speed(speed_raw)
                line = f'{ip}:{port}#{flag} | {city} | ⬇️{speed_mb:.1f}MB/s | ❤️CF'
                lines.append(line)
    except Exception as e:
        print(f'{C.RED}[iptest] 解析结果失败: {e}{C.RESET}')
        return None

    # 写出重整后的结果文件 (UTF-8)
    with open(result_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + ('\n' if lines else ''))

    print(f'  {C.GREEN}iptest 测速完成, 共 {len(lines)} 条结果{C.RESET}')
    print(f'  结果文件: {result_file}')
    print()
    for ln in lines:
        print(f'  {ln}')

    return lines


# ============================================================
# CLI 主入口
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description='Cloudflare CDN IP 三网检测脚本',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  python cf_tri_net_detect.py 172.64.229.0/22
  python cf_tri_net_detect.py 172.64.229.0/22 --top 30
  python cf_tri_net_detect.py 172.64.229.0/22 --ports 80,443,2052,2083
  python cf_tri_net_detect.py 172.64.229.0/22 --threads 100 --no-trace
  python cf_tri_net_detect.py 172.64.229.0/22 --sample 50
        '''
    )
    parser.add_argument('cidr', nargs='?', default='172.64.229.0/22',
                        help='目标 CIDR 网段 (默认: 172.64.229.0/22)')
    parser.add_argument('--ports', default='80,443,2052,2083,2086,2087,2095,2096',
                        help='TCP 检测端口, 逗号分隔 (默认: 80,443,2052,2083,2086,2087,2095,2096)')
    parser.add_argument('--threads', type=int, default=50,
                        help='并行线程数 (默认: 50)')
    parser.add_argument('--top', type=int, default=50,
                        help='路由追踪 Top N (默认: 50)。对 RTT 最低的 N 个响应 IP 执行 traceroute，'
                             '用于三网骨干识别。N 越大覆盖越全但耗时增加 (每 IP 约 3-15s)。'
                             '设为 0 禁用 traceroute')
    parser.add_argument('--no-trace', action='store_true',
                        help='跳过路由追踪')
    parser.add_argument('--sample', type=int, default=None,
                        help='抽样测试数量 (不指定则全量)')
    parser.add_argument('--output', '-o', default=None,
                        help='输出报告文件名前缀 (默认: cf_report_<cidr>_<timestamp>)')
    parser.add_argument('--display', type=int, default=30,
                        help='控制台显示前 N 条结果 (默认: 30)')
    parser.add_argument('--no-isp', action='store_true',
                        help='跳过本地 ISP 检测')
    parser.add_argument('--ping-count', type=int, default=3,
                        help='每个 IP 的 ping 次数 (默认: 3, 大网段建议 2)')
    parser.add_argument('--csv', action='store_true',
                        help='输出 CSV 文件 (Excel 兼容, UTF-8 BOM)')
    parser.add_argument('--no-json', action='store_true',
                        help='不输出 JSON 报告')
    parser.add_argument('--no-txt', action='store_true',
                        help='不输出 TXT 文本报告')
    parser.add_argument('--csv-only', action='store_true',
                        help='仅输出 CSV 报告 (等价 --no-json --no-txt, 并强制输出 CSV)')
    parser.add_argument('--cidr-file', default=None,
                        help='从文件读取 CIDR 列表 (一行一个, 支持 # 注释)。'
                             '例如 cidr.txt 内容为: 172.64.229.0/22')
    parser.add_argument('--ip-txt', action='store_true',
                        help='同步输出 ip.txt (格式: "IP 端口", 空格分隔), 供 CF 优选工具使用')
    parser.add_argument('--ip-txt-port', type=int, default=443,
                        help='ip.txt 中使用的端口 (默认: 443)')
    parser.add_argument('--ip-txt-all', action='store_true',
                        help='ip.txt 包含全部响应 IP (默认仅包含适合CF优选的 IP)')
    parser.add_argument('--iptest', action='store_true',
                        help='输出 ip.txt 后自动调用 iptest.exe 进行优选测速 (重整为 "IP:端口#国旗 | 城市 | ⬇️X.XMB/s | ❤️CF" 格式)')
    parser.add_argument('--iptest-exe', default=None,
                        help='iptest.exe 路径 (默认: 脚本同目录下的 iptest.exe)')
    parser.add_argument('--iptest-delay', type=int, default=0,
                        help='iptest 延迟阈值 ms (默认: 0, 禁用)')
    parser.add_argument('--iptest-speedtest', type=int, default=5,
                        help='iptest 下载测速并发数 (默认: 5, 0=禁用)')
    parser.add_argument('--iptest-max', type=int, default=100,
                        help='iptest 并发协程数 (默认: 100)')
    parser.add_argument('--min-speed', type=float, default=0.0,
                        help='下载速度阈值 (MB/s): 仅输出实测下载速度 >= 该值的 IP, '
                             '并丢弃测速失败(0 kB/s)的 IP。默认 0.0 = 保留所有有真实速度的 IP; '
                             '上调该值可进一步收紧筛选 (如 --min-speed 10 仅保留 >=10MB/s)')

    args = parser.parse_args()

    # 强制 stdout/stderr 使用 UTF-8 (避免 Windows GBK 控制台/重定向时的编码错误)
    try:
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8')
            sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

    # 解析端口
    ports = [int(p.strip()) for p in args.ports.split(',')]

    # 确定待扫描的 CIDR 列表 (支持从文件读取)
    if args.cidr_file:
        cidr_list = load_cidr_file(args.cidr_file)
        if not cidr_list:
            print(f'\n{C.RED}CIDR 文件为空: {args.cidr_file}{C.RESET}')
            sys.exit(1)
        print(f'{C.CYAN}已从文件读取 {len(cidr_list)} 个 CIDR:{C.RESET} {args.cidr_file}')
    else:
        cidr_list = [args.cidr]

    print_banner()

    # ISP 检测
    local_isp = None
    if not args.no_isp:
        print(f'{C.BOLD}{C.BLUE}━━━ 本地 ISP 检测 ━━━{C.RESET}')
        local_isp = detect_local_isp()
        if local_isp and local_isp.get('isp_cn') != '未知':
            print(f'  {C.GREEN}ISP:{C.RESET} {local_isp["isp_cn"]} ({local_isp.get("isp", "")})')
            print(f'  {C.GREEN}IP:{C.RESET}  {local_isp.get("ip", "")}')
            print(f'  {C.GREEN}城市:{C.RESET} {local_isp.get("city", "")}')
        else:
            print(f'  {C.YELLOW}无法检测本地 ISP (不影响检测){C.RESET}')
        print()

    # 逐个网段扫描并聚合结果
    all_results = []
    merged = {
        'total_ips': 0,
        'responsive': 0,
        'unresponsive': 0,
        'colo_distribution': {},
        'quality_distribution': {'premium': 0, 'good': 0, 'normal': 0, 'poor': 0},
        'cf_optimization_count': 0,
        'rare_premium_count': 0,
        'avg_rtt': 0.0,
        '_rtt_sum': 0.0,
        '_rtt_n': 0,
        'min_rtt': None,
        'duration': 0.0,
    }
    multi = len(cidr_list) > 1

    for idx, c in enumerate(cidr_list, 1):
        if multi:
            print(f'\n{C.BOLD}{C.MAGENTA}═══ 网段 {idx}/{len(cidr_list)}: {c} ══{C.RESET}\n')
        results, summary, scan_info = scan_range(
            cidr=c,
            threads=args.threads,
            ports=ports,
            top_n=args.top,
            do_trace=not args.no_trace,
            sample=args.sample,
            ping_count=args.ping_count,
            silent=multi,
        )
        all_results.extend(results)

        # 聚合汇总
        merged['total_ips'] += summary.get('total_ips', 0)
        merged['responsive'] += summary.get('responsive', 0)
        merged['unresponsive'] += summary.get('unresponsive', 0)
        for k, v in summary.get('colo_distribution', {}).items():
            merged['colo_distribution'][k] = merged['colo_distribution'].get(k, 0) + v
        for k in ('premium', 'good', 'normal', 'poor'):
            merged['quality_distribution'][k] += summary.get('quality_distribution', {}).get(k, 0)
        merged['cf_optimization_count'] += summary.get('cf_optimization_count', 0)
        merged['rare_premium_count'] += summary.get('rare_premium_count', 0)
        merged['duration'] += summary.get('duration', 0)
        # 加权平均 RTT
        rtts = [r['icmp_rtt'] for r in results if r.get('icmp_rtt')]
        if rtts:
            merged['_rtt_sum'] += sum(rtts)
            merged['_rtt_n'] += len(rtts)
            merged['min_rtt'] = min(merged['min_rtt'], min(rtts)) if merged['min_rtt'] is not None else min(rtts)

    # 计算合并后的平均 RTT
    merged['avg_rtt'] = round(merged['_rtt_sum'] / max(1, merged['_rtt_n']), 1)
    del merged['_rtt_sum']
    del merged['_rtt_n']

    results = all_results
    summary = merged
    cidr_label = f'{len(cidr_list)} 个网段' if multi else cidr_list[0]
    scan_info = {
        'cidr': cidr_label,
        'total': merged['total_ips'],
        'responsive': merged['responsive'],
        'ports': ports,
        'threads': args.threads,
        'sample': args.sample,
        'scan_time': now_str(),
        'duration': merged['duration'],
    }

    if not results:
        print(f'\n{C.RED}未检测到任何响应 IP，请检查网络连接或目标网段。{C.RESET}')
        sys.exit(1)

    # 先保存文件报告 (防御性: 即使控制台打印失败, 文件也已生成)
    ts = timestamp_str()
    if multi:
        cidr_safe = 'combined'
    else:
        cidr_safe = sanitize_cidr(cidr_list[0])
    prefix = args.output or f'cf_report_{cidr_safe}_{ts}'

    output_dir = os.path.dirname(os.path.abspath(__file__))

    json_file = os.path.join(output_dir, f'{prefix}.json')
    text_file = os.path.join(output_dir, f'{prefix}.txt')
    csv_file = os.path.join(output_dir, f'{prefix}.csv')
    top_file = os.path.join(output_dir, f'cf_top_ips_{cidr_safe}_{ts}.txt')
    ip_file = os.path.join(output_dir, 'ip.txt')

    # ---- 步骤1: 生成 ip.txt (优选 IP, 作为 iptest 实测输入) ----
    # 必须在 iptest 之前, 保证测速对象是本轮优选出来的 IP
    if args.ip_txt:
        save_ip_port_list(results, ip_file, port=args.ip_txt_port, only_optimal=not args.ip_txt_all)

    # ---- 步骤2: iptest 实名测速 (必须在报告之前, 保证报告速度来自本轮实测) ----
    # 触发条件: 显式 --iptest, 或已开启 --ip-txt (ip.txt 即为测速输入)
    if args.iptest or args.ip_txt:
        if not os.path.exists(ip_file):
            # 仅 --iptest 时确保 ip.txt 存在 (作为测速输入)
            if args.iptest:
                save_ip_port_list(results, ip_file, port=args.ip_txt_port, only_optimal=not args.ip_txt_all)
        if os.path.exists(ip_file):
            run_iptest_speedtest(
                ip_file,
                script_dir=output_dir,
                iptest_exe=args.iptest_exe,
                delay=args.iptest_delay,
                speedtest=args.iptest_speedtest,
                maxc=args.iptest_max,
                min_speed_mb=args.min_speed,
                result_file=os.path.join(output_dir, 'iptest_result.txt'),
            )
            # 用本轮实测速度回填分析结果 (修复: 之前综合阶段读取的是陈旧/空的 iptest_raw.csv)
            _full = os.path.join(output_dir, 'iptest_raw_full.csv')
            _src = _full if os.path.exists(_full) else os.path.join(output_dir, 'iptest_raw.csv')
            if os.path.exists(_src):
                _fresh = parse_iptest_speed_results(_src)
                if _fresh:
                    # 先清空可能来自陈旧文件的速度, 杜绝污染
                    for r in results:
                        r['download_speed_mb'] = None
                    for r in results:
                        sp = _fresh.get(r['ip'])
                        if sp:
                            r['download_speed_mb'] = round(sp['speed_mb'], 1) if sp['speed_mb'] else None
                            port_443_ok = (r.get('tcp_rtts') or {}).get('443') is not None
                            r['composite_score'], r['composite_breakdown'] = composite_score(
                                r.get('icmp_rtt'), r.get('tcp_median_rtt'), r.get('tcp_jitter'),
                                r['download_speed_mb'], r.get('route_quality'), r.get('cf_colo'), port_443_ok)
                    has_speed = any(r.get('download_speed_mb') for r in results)
                    if has_speed:
                        results.sort(key=lambda x: (x.get('composite_score') or 0), reverse=True)
                    summary['has_speed_data'] = has_speed
                    summary['avg_composite_score'] = round(
                        sum(r.get('composite_score', 0) for r in results) / max(1, len(results)), 1
                    ) if results else 0
                    summary['max_composite_score'] = max(
                        (r.get('composite_score', 0) for r in results), default=0
                    )
                    print(f'  {C.CYAN}[iptest] 已用本轮实测速度回填 {len(_fresh)} 条结果{C.RESET}')
        else:
            print(f'{C.YELLOW}未找到 ip.txt, 跳过 iptest 测速{C.RESET}')

    # ---- 步骤3: 保存报告 (此刻 CSV 报告的下载速度已是本轮 iptest 实测) ----
    print(f'{C.BOLD}{C.BLUE}━━━ 报告文件 ━━━{C.RESET}')
    if args.csv_only:
        # 仅输出 CSV: 等价于 --no-json --no-txt 并强制写 CSV
        if not args.csv:
            args.csv = True
        if not args.no_json:
            args.no_json = True
        if not args.no_txt:
            args.no_txt = True
    if not args.no_json:
        save_json_report(results, summary, scan_info, local_isp, json_file)
    if not args.no_txt:
        save_text_report(results, summary, scan_info, local_isp, text_file)
    if args.csv:
        save_csv_report(results, summary, scan_info, local_isp, csv_file, ports)
    save_top_ips(results, top_file, count=20)

    # 打印控制台报告 (防御性: 编码异常不影响文件输出)
    try:
        print_console_report(results, summary, scan_info, local_isp, top_display=args.display)
    except UnicodeEncodeError:
        # 控制台不支持 UTF-8 时的降级处理
        print('\n[注意] 控制台编码不支持部分 Unicode 字符, 详细结果请查看文本/CSV 报告。')
        print(f'  网段: {scan_info["cidr"]}  响应: {summary["responsive"]}/{summary["total_ips"]}'
              f'  平均RTT: {summary["avg_rtt"]}ms')
        print(f'  CF优选推荐: {summary["cf_optimization_count"]}  稀有优质段: {summary["rare_premium_count"]}')

    print(f'\n{C.GREEN}{C.BOLD}检测完成! 总耗时 {summary["duration"]} 秒{C.RESET}\n')


if __name__ == '__main__':
    main()
