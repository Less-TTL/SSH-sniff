#!/usr/bin/env python3
import argparse
import asyncio
import itertools
import json
import os
import sys
import signal
import socket
import time
import subprocess
import re
from datetime import datetime
from colorama import Fore, Style, init
from typing import Dict, Iterable, List, Optional
from xro_scanner import (
    scan_targets, parse_ports, validate_and_expand_targets, 
    generate_random_public_ips, DEFAULT_PORTS, detect_device_type, 
    scan_with_rustscan, tcp_check
)

init(autoreset=True)

_tmp = {}
_fpath = "xro_results.json"
_stop = False

COLORS = [
    Fore.LIGHTCYAN_EX,
]

class IntelligenceGatherer:
    
    def __init__(self, timeout=5):
        self.t = timeout
        self.c = {}
    
    def get_whois_info(self, addr):
        if addr in self.c:
            return self.c[addr].get('whois')
        
        d = {
            'organization': 'Unknown',
            'country': 'Unknown',
            'netname': 'Unknown',
            'description': 'Unknown',
            'abuse_contact': 'Unknown',
            'cidr': 'Unknown'
        }
        
        try:
            r = subprocess.run(
                ['whois', addr],
                capture_output=True,
                text=True,
                timeout=self.t
            )
            
            if r.returncode == 0:
                txt = r.stdout
                
                pats = {
                    'organization': [
                        r'(?:OrgName|Organization|org-name|owner):\s*(.+)',
                        r'(?:descr):\s*(.+)'
                    ],
                    'country': [
                        r'(?:Country|country):\s*([A-Z]{2})'
                    ],
                    'netname': [
                        r'(?:NetName|netname):\s*(.+)'
                    ],
                    'abuse_contact': [
                        r'(?:OrgAbuseEmail|abuse-mailbox|e-mail):\s*(.+)'
                    ],
                    'cidr': [
                        r'(?:CIDR|inetnum):\s*(.+)'
                    ]
                }
                
                for k, v in pats.items():
                    for p in v:
                        m = re.search(p, txt, re.IGNORECASE | re.MULTILINE)
                        if m:
                            d[k] = m.group(1).strip()
                            break
                
                desc = re.findall(r'descr:\s*(.+)', txt, re.IGNORECASE)
                if desc:
                    for x in desc:
                        if x.strip() and len(x.strip()) > 5:
                            d['description'] = x.strip()
                            break
        
        except subprocess.TimeoutExpired:
            d['error'] = 'WHOIS timeout'
        except FileNotFoundError:
            d['error'] = 'WHOIS not installed'
        except Exception as e:
            d['error'] = f'WHOIS error: {str(e)}'
        
        return d
    
    def get_geolocation(self, addr):
        d = {
            'city': 'Unknown',
            'region': 'Unknown',
            'country': 'Unknown',
            'isp': 'Unknown',
            'org': 'Unknown',
            'as': 'Unknown',
            'lat': None,
            'lon': None,
            'timezone': 'Unknown'
        }
        
        try:
            import urllib.request
            import urllib.error
            
            u = f'http://ip-api.com/json/{addr}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname'
            
            req = urllib.request.Request(u)
            req.add_header('User-Agent', 'XRO-Scanner/1.0')
            
            with urllib.request.urlopen(req, timeout=self.t) as resp:
                j = json.loads(resp.read().decode())
                
                if j.get('status') == 'success':
                    d = {
                        'city': j.get('city', 'Unknown'),
                        'region': j.get('regionName', 'Unknown'),
                        'country': j.get('country', 'Unknown'),
                        'country_code': j.get('countryCode', 'Unknown'),
                        'isp': j.get('isp', 'Unknown'),
                        'org': j.get('org', 'Unknown'),
                        'as': j.get('as', 'Unknown'),
                        'asname': j.get('asname', 'Unknown'),
                        'lat': j.get('lat'),
                        'lon': j.get('lon'),
                        'timezone': j.get('timezone', 'Unknown'),
                        'zip': j.get('zip', 'Unknown')
                    }
                else:
                    d['error'] = j.get('message', 'Geolocation failed')
        
        except Exception as e:
            d['error'] = f'Geolocation error: {str(e)}'
        
        return d
    
    def get_dns_info(self, addr):
        d = {
            'hostname': 'Unknown',
            'ptr_records': [],
            'has_reverse_dns': False
        }
        
        try:
            h, al, ip = socket.gethostbyaddr(addr)
            d['hostname'] = h
            d['ptr_records'] = [h] + al
            d['has_reverse_dns'] = True
        except socket.herror:
            d['error'] = 'No reverse DNS'
        except Exception as e:
            d['error'] = f'DNS error: {str(e)}'
        
        return d
    
    def check_reputation(self, addr):
        rep = {
            'is_proxy': False,
            'is_vpn': False,
            'is_tor': False,
            'is_hosting': False,
            'is_cloud': False,
            'risk_score': 0
        }
        
        try:
            w = self.get_whois_info(addr)
            g = self.get_geolocation(addr)
            
            org_str = (w.get('organization', '') + ' ' + g.get('org', '')).lower()
            isp_str = g.get('isp', '').lower()
            
            cloud_keys = ['amazon', 'aws', 'google', 'microsoft', 'azure', 'digitalocean', 
                            'linode', 'vultr', 'ovh', 'hetzner', 'alibaba', 'oracle']
            vpn_keys = ['vpn', 'proxy', 'private internet access', 'nordvpn', 'expressvpn']
            host_keys = ['hosting', 'server', 'datacenter', 'data center', 'colocation']
            
            for k in cloud_keys:
                if k in org_str or k in isp_str:
                    rep['is_cloud'] = True
                    rep['risk_score'] += 10
                    break
            
            for k in vpn_keys:
                if k in org_str or k in isp_str:
                    rep['is_vpn'] = True
                    rep['risk_score'] += 30
                    break
            
            for k in host_keys:
                if k in org_str or k in isp_str:
                    rep['is_hosting'] = True
                    rep['risk_score'] += 5
                    break
        
        except Exception as e:
            rep['error'] = str(e)
        
        return rep
    
    def gather_full_intel(self, addr):
        print(f"{Fore.CYAN}[*] Gathering intelligence on {addr}...{Style.RESET_ALL}")
        
        data = {
            'ip': addr,
            'timestamp': datetime.now().isoformat(),
            'whois': {},
            'geolocation': {},
            'dns': {},
            'reputation': {}
        }
        
        print(f"{Fore.YELLOW}  → WHOIS lookup...{Style.RESET_ALL}")
        data['whois'] = self.get_whois_info(addr)
        
        print(f"{Fore.YELLOW}  → Geolocation lookup...{Style.RESET_ALL}")
        data['geolocation'] = self.get_geolocation(addr)
        
        print(f"{Fore.YELLOW}  → DNS lookup...{Style.RESET_ALL}")
        data['dns'] = self.get_dns_info(addr)
        
        print(f"{Fore.YELLOW}  → Reputation check...{Style.RESET_ALL}")
        data['reputation'] = self.check_reputation(addr)
        
        self.c[addr] = data
        return data


class HoneypotAnalyzer:
    
    def __init__(self):
        self.sigs = {
            'kippo': 100,
            'cowrie': 100,
            'honeypot': 100,
            'honeyd': 95,
            'artillery': 90,
            'SSH-2.0-OpenSSH_3.': 75,
            'SSH-1.99': 80,
            'SSH-2.0-OpenSSH_4.': 55,
        }
    
    def analyze_banner(self, b):
        import re
        sc = 0
        fl = []
        
        if not b:
            return sc, fl
        
        bn = b.lower()
        
        for s, v in self.sigs.items():
            if s.lower() in bn:
                sc += v
                fl.append(f"Signature match: {s}")
        
        if len(b) > 200:
            sc += 30
            fl.append("Abnormally long banner")
        
        if 'openssh' in bn and not re.search(r'\d+\.\d+', b):
            sc += 25
            fl.append("Missing version number")
            
        return sc, fl
    
    def analyze_timing(self, samps):
        if len(samps) < 3:
            return 0, []
        
        avg = sum(samps) / len(samps)
        var = sum((x - avg) ** 2 for x in samps) / len(samps)
        std = var ** 0.5
        
        fl = []
        sc = 0
        
        if var < 0.0001 and avg < 0.05:
            sc += 60
            fl.append(f"Robotic timing pattern (σ²={var:.6f})")
        elif std < 0.01 and avg < 0.1:
            sc += 35
            fl.append(f"Suspiciously low variance (σ={std:.4f})")
        
        if avg > 2.0:
            sc += 20
            fl.append(f"Delayed responses (avg={avg:.2f}s)")
            
        return sc, fl
    
    def analyze_multi_ssh(self, pts):
        cnt = len(pts)
        sc = 0
        fl = []
        
        if cnt > 3:
            sc += 85
            fl.append(f"Excessive SSH ports ({cnt})")
        elif cnt > 2:
            sc += 60
            fl.append(f"Multiple SSH ports ({cnt})")
        elif cnt == 2:
            sc += 30
            fl.append("Dual SSH configuration")
        
        if 2222 in pts and 22 in pts:
            sc += 15
            fl.append("Common honeypot port combo (22+2222)")
            
        return sc, fl
    
    def analyze_tcp_fingerprint(self, sk):
        sc = 0
        fl = []
        
        try:
            w = sk.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            if w == 65535 or w == 8192:
                sc += 15
                fl.append(f"Default TCP window ({w})")
        except:
            pass
            
        return sc, fl


class NetworkProber:
    
    def __init__(self, timeout=3):
        self.t = timeout
        self.ana = HoneypotAnalyzer()
        self.intel = IntelligenceGatherer(timeout=timeout)
        
    def check_alive(self, addr):
        pts = [22, 80, 443]
        
        for p in pts:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                res = s.connect_ex((addr, p))
                s.close()
                
                if res == 0:
                    return True, p
            except:
                continue
                
        return False, None
    
    def probe_ssh(self, addr, pt):
        times = []
        d = {
            'port': pt,
            'alive': False,
            'banner': None,
            'hp_score': 0,
            'flags': [],
            'tcp_info': {}
        }
        
        for _ in range(4):
            try:
                t0 = time.time()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.t)
                
                conn = s.connect_ex((addr, pt))
                
                if conn == 0:
                    d['alive'] = True
                    
                    sc, fl = self.ana.analyze_tcp_fingerprint(s)
                    d['hp_score'] += sc
                    d['flags'].extend(fl)
                    
                    try:
                        s.settimeout(2.5)
                        raw = s.recv(2048)
                        bn = raw.decode('utf-8', errors='ignore').strip()
                        d['banner'] = bn
                        
                        sc, fl = self.ana.analyze_banner(bn)
                        d['hp_score'] += sc
                        d['flags'].extend(fl)
                    except socket.timeout:
                        d['hp_score'] += 25
                        d['flags'].append("Banner timeout (suspicious)")
                    except:
                        pass
                    
                    elapsed = time.time() - t0
                    times.append(elapsed)
                
                s.close()
                time.sleep(0.08)
                
            except Exception:
                pass
        
        if times:
            sc, fl = self.ana.analyze_timing(times)
            d['hp_score'] += sc
            d['flags'].extend(fl)
            d['tcp_info']['avg_time'] = sum(times) / len(times)
            
        return d
    
    def full_scan(self, addr, ssh_pts, gather_intel=False):
        r = {
            'ip': addr,
            'active': False,
            'ssh': {},
            'total_hp_score': 0,
            'verdict': 'UNKNOWN',
            'risk_level': 0
        }
        
        alive, alive_pt = self.check_alive(addr)
        
        if not alive:
            r['verdict'] = 'OFFLINE'
            return r
        
        r['active'] = True
        
        if gather_intel:
            r['intelligence'] = self.intel.gather_full_intel(addr)
        
        active_pts = []
        for p in ssh_pts:
            ssh_d = self.probe_ssh(addr, p)
            if ssh_d['alive']:
                r['ssh'][p] = ssh_d
                r['total_hp_score'] += ssh_d['hp_score']
                active_pts.append(p)
        
        if len(active_pts) > 1:
            sc, fl = self.ana.analyze_multi_ssh(active_pts)
            r['total_hp_score'] += sc
            
            if active_pts:
                first = active_pts[0]
                r['ssh'][first]['flags'].extend(fl)
        
        sc = r['total_hp_score']
        
        if sc >= 100:
            r['verdict'] = 'HONEYPOT'
            r['risk_level'] = 5
        elif sc >= 70:
            r['verdict'] = 'LIKELY_HONEYPOT'
            r['risk_level'] = 4
        elif sc >= 45:
            r['verdict'] = 'SUSPICIOUS'
            r['risk_level'] = 3
        elif sc >= 25:
            r['verdict'] = 'CAUTION'
            r['risk_level'] = 2
        else:
            r['verdict'] = 'CLEAN'
            r['risk_level'] = 1
            
        return r


def rainbow_text(text: str, bright: bool = True, repeat: int = 2) -> str:
    if not text:
        return ""
    styled = []
    colors = itertools.cycle(COLORS)
    cur = next(colors)
    vis_cnt = 0
    for ch in text:
        if ch == "\n":
            styled.append(Style.RESET_ALL + "\n")
            cur = next(colors)
            vis_cnt = 0
            continue
        if not ch.strip():
            styled.append(ch)
            continue
        if vis_cnt >= repeat:
            cur = next(colors)
            vis_cnt = 0
        pfx = cur + (Style.BRIGHT if bright else "")
        styled.append(pfx + ch)
        vis_cnt += 1
    styled.append(Style.RESET_ALL)
    return "".join(styled)

def rainbow_print(text: str, bright: bool = True, repeat: int = 2) -> None:
    print(rainbow_text(text, bright=bright, repeat=repeat))

def render_panel(title: str) -> None:
    w = 61
    c = Fore.LIGHTCYAN_EX + Style.BRIGHT
    print(c + "╔" + "═" * w + "╗" + Style.RESET_ALL)
    print(c + f"║{title:^{w}}║" + Style.RESET_ALL)
    print(c + "╚" + "═" * w + "╝" + Style.RESET_ALL)

def print_banner():
    w = 61
    c = Fore.LIGHTCYAN_EX + Style.BRIGHT
    print()
    print(c + "╔" + "═" * w + "╗" + Style.RESET_ALL)
    print(c + f"║{'XRO V2':^{w}}║" + Style.RESET_ALL)
    print(c + f"║{'Intelligence-Enhanced Scanner':^{w}}║" + Style.RESET_ALL)
    print(c + "╚" + "═" * w + "╝" + Style.RESET_ALL)

def signal_handler(signum, frame):
    global _stop, _tmp, _fpath
    _stop = True
    
    print(Fore.YELLOW + "\n\n[!] Scan interrupted by user (Ctrl+C)" + Style.RESET_ALL)
    print(Fore.CYAN + "[*] Saving partial results..." + Style.RESET_ALL)
    
    if _tmp:
        if save_partial_results(_tmp, _fpath, interrupted=True):
            print(Fore.GREEN + "\n✓ Partial results saved successfully!" + Style.RESET_ALL)
            print(Fore.WHITE + f"  You can view them in: {_fpath}" + Style.RESET_ALL)
        else:
            print(Fore.RED + "\n✗ Failed to save partial results" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "[!] No results collected yet" + Style.RESET_ALL)
    
    print(Fore.YELLOW + "\nExiting..." + Style.RESET_ALL)
    sys.exit(0)

def save_partial_results(res: Dict, out: str, interrupted: bool = False):
    if not res:
        print(Fore.YELLOW + "\n[!] No results to save." + Style.RESET_ALL)
        return
    
    for addr, d in res.items():
        if "ports" in d:
            pts = d["ports"]
            open_cnt = sum(1 for p in pts if p["status"] == "open")
            d["summary"] = {
                "has_open": open_cnt > 0,
                "open_count": open_cnt,
                "total_ports": len(pts),
            }
            d["device_type"] = detect_device_type(pts)
    
    active = sum(1 for d in res.values() if d.get("summary", {}).get("has_open", False))
    meta = {
        "scan_info": {
            "total_ips_scanned": len(res),
            "active_hosts_found": active,
            "scan_status": "interrupted" if interrupted else "completed",
        },
        "timestamp": datetime.now().isoformat(),
    }
    
    try:
        with open(out, "w") as f:
            json.dump({"meta": meta, "results": res}, f, indent=2)
        
        if interrupted:
            print(Fore.YELLOW + f"\n\n{'='*80}")
            print(Fore.YELLOW + "  SCAN INTERRUPTED - PARTIAL RESULTS SAVED")
            print(Fore.YELLOW + f"{'='*80}" + Style.RESET_ALL)
        print(Fore.GREEN + f"✓ Results saved to: {out}")
        print(Fore.CYAN + f"  • IPs scanned: {len(res)}")
        print(Fore.CYAN + f"  • Active hosts: {active}" + Style.RESET_ALL)
        return True
    except Exception as e:
        print(Fore.RED + f"[!] Failed to save results: {e}" + Style.RESET_ALL)
        return False


def perform_mass_scan(timeout, output, misc_opts, concurrency=500, batch_size=100):
    global _tmp, _fpath, _stop
    
    if not misc_opts.get("allow_public"):
        print(Fore.RED + "[!] Mass scan requires allow_public to be enabled.")
        return
    
    ssh_pts = [22, 2222, 2200, 22222]
    
    _fpath = output
    _stop = False
    signal.signal(signal.SIGINT, signal_handler)
    
    os.system('cls' if os.name == 'nt' else 'clear')
    print_banner()
    
    print(Fore.CYAN + f"\n[+] Starting automatic mass scanner")
    print(Fore.CYAN + f"[+] Scanning for SSH servers on ports: {', '.join(map(str, ssh_pts))}")
    print(Fore.YELLOW + "[+] Mode: CONTINUOUS")
    print(Fore.YELLOW + "[TIP] Press Ctrl+C to stop and save results\n" + Style.RESET_ALL)
    
    tot_scan = 0
    tot_found = 0
    batch_n = 0
    
    try:
        while True:
            if _stop:
                break
                
            batch_n += 1
            print(Fore.MAGENTA + f"\n{'='*80}")
            print(Fore.MAGENTA + f"  BATCH #{batch_n} - Generating {batch_size} random IPs...")
            print(Fore.MAGENTA + f"{'='*80}" + Style.RESET_ALL)
            
            tgts = generate_random_public_ips(count=batch_size)
            
            if not tgts:
                print(Fore.RED + "[!] Failed to generate IPs. Retrying...")
                continue
            
            print(Fore.GREEN + f"[✓] Generated {len(tgts)} IPs - Starting scan..." + Style.RESET_ALL)
            
            def rustscan_prog(addr: str, is_valid: Optional[bool]) -> None:
                if is_valid is None:
                    print(Fore.CYAN + f"[Scanning] {addr}...".ljust(80) + Style.RESET_ALL, end='\r')
                elif is_valid:
                    print(Fore.GREEN + f"[✓ FOUND] {addr} - SSH Server detected!".ljust(80) + Style.RESET_ALL)
            
            rust_res = scan_with_rustscan(tgts, ssh_pts, timeout, progress_cb=rustscan_prog)
            
            if not rust_res:
                print(Fore.YELLOW + "[*] Using Python-based scanning..." + Style.RESET_ALL)
                
                def prog_fmt(addr: str, pt: int, msg: str) -> None:
                    if "open" in msg.lower():
                        print(Fore.GREEN + f"[{addr}:{pt}] {msg}" + Style.RESET_ALL)
                
                scan_res = asyncio.run(scan_targets(
                    tgts,
                    ssh_pts,
                    protocol='tcp',
                    concurrency=concurrency,
                    timeout=timeout,
                    progress_cb=prog_fmt,
                ))
                
                rust_res = {}
                for addr, d in scan_res.items():
                    open_pts = [p["port"] for p in d["ports"] if p["status"] == "open"]
                    rust_res[addr] = open_pts

            batch_found = 0
            for addr, open_pts in rust_res.items():
                if open_pts:
                    batch_found += 1
                    if addr not in _tmp:
                        _tmp[addr] = {"summary": None, "device_type": None, "ports": []}
                    
                    for pt in ssh_pts:
                        st = "open" if pt in open_pts else "closed"
                        _tmp[addr]["ports"].append({
                            "port": pt,
                            "protocol": "TCP",
                            "status": st,
                            "info": "SSH" if st == "open" else ""
                        })
            
            tot_scan += len(tgts)
            tot_found += batch_found
            
            print(Fore.CYAN + f"\n[Batch #{batch_n} Summary]")
            print(Fore.WHITE + f"  • IPs scanned: {len(tgts)}")
            print(Fore.GREEN + f"  • SSH servers found: {batch_found}")
            print(Fore.YELLOW + f"[Total] Scanned: {tot_scan} | Found: {tot_found}" + Style.RESET_ALL)
            
            if batch_n % 5 == 0:
                save_partial_results(_tmp, output, interrupted=False)
                
    except KeyboardInterrupt:
        pass
    finally:
        if _tmp:
            print(Fore.CYAN + "\n[*] Saving final results..." + Style.RESET_ALL)
            save_partial_results(_tmp, output, interrupted=_stop)
        
        signal.signal(signal.SIGINT, signal.SIG_DFL)


def select_file():
    print()
    render_panel("FILE SELECTION")
    
    jfiles = [f for f in os.listdir('.') if f.endswith('.json')]
    
    if jfiles:
        print(f"\n{Fore.GREEN}Available JSON files:{Style.RESET_ALL}")
        for i, fn in enumerate(jfiles, 1):
            print(f"  {Fore.YELLOW}[{i}]{Style.RESET_ALL} {fn}")
        print(f"  {Fore.YELLOW}[0]{Style.RESET_ALL} Enter custom path")
    else:
        print(f"{Fore.YELLOW}No JSON files found in current directory{Style.RESET_ALL}")
    
    while True:
        try:
            inp = input(f"\n{Style.BRIGHT}Select file number or enter path: {Style.RESET_ALL}").strip()
            
            if inp == '0' or not jfiles:
                fp = input(f"{Style.BRIGHT}Enter JSON file path: {Style.RESET_ALL}").strip()
            elif inp.isdigit() and 1 <= int(inp) <= len(jfiles):
                fp = jfiles[int(inp) - 1]
            else:
                fp = inp
            
            if os.path.exists(fp):
                return fp
            else:
                print(f"{Fore.RED}[!] File not found: {fp}{Style.RESET_ALL}")
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[!] Cancelled{Style.RESET_ALL}")
            return None

def parse_targets(fp):
    try:
        with open(fp, 'r') as f:
            d = json.load(f)
        
        tgts = {}
        
        if 'results' in d:
            for addr, info in d['results'].items():
                ssh_p = []
                
                if 'ports' in info:
                    for pinfo in info['ports']:
                        if pinfo.get('status') == 'open':
                            ssh_p.append(pinfo['port'])
                
                if ssh_p:
                    tgts[addr] = ssh_p
        
        return tgts
    except Exception as e:
        print(f"{Fore.RED}[!] Error parsing JSON: {e}{Style.RESET_ALL}")
        return {}

def show_progress(cur, tot, addr):
    pct = int((cur / tot) * 100)
    bar_len = 40
    fill = int(bar_len * cur / tot)
    bar = '█' * fill + '░' * (bar_len - fill)
    
    print(f"\r{Fore.CYAN}[{bar}] {pct}% {Style.RESET_ALL} Scanning: {Fore.YELLOW}{addr:<15}{Style.RESET_ALL}", end='', flush=True)

def display_intelligence(intel):
    if not intel:
        return
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'─' * 60}{Style.RESET_ALL}")
    print(f"{Fore.LIGHTCYAN_EX}{Style.BRIGHT}📊 INTELLIGENCE REPORT{Style.RESET_ALL}")
    print(f"{Fore.LIGHTCYAN_EX}{'─' * 60}{Style.RESET_ALL}")
    
    w = intel.get('whois', {})
    if w and not w.get('error'):
        print(f"\n{Fore.YELLOW}🏢 Organization Information:{Style.RESET_ALL}")
        print(f"  └─ Owner: {Fore.WHITE}{w.get('organization', 'Unknown')}{Style.RESET_ALL}")
        print(f"  └─ Network: {Fore.WHITE}{w.get('netname', 'Unknown')}{Style.RESET_ALL}")
        print(f"  └─ CIDR: {Fore.WHITE}{w.get('cidr', 'Unknown')}{Style.RESET_ALL}")
        print(f"  └─ Country: {Fore.WHITE}{w.get('country', 'Unknown')}{Style.RESET_ALL}")
        
        if w.get('description') != 'Unknown':
            print(f"  └─ Description: {Fore.WHITE}{w.get('description')}{Style.RESET_ALL}")
        
        if w.get('abuse_contact') != 'Unknown':
            print(f"  └─ Abuse Contact: {Fore.WHITE}{w.get('abuse_contact')}{Style.RESET_ALL}")
    
    g = intel.get('geolocation', {})
    if g and not g.get('error'):
        print(f"\n{Fore.YELLOW}🌍 Geolocation:{Style.RESET_ALL}")
        print(f"  └─ Location: {Fore.WHITE}{g.get('city', 'Unknown')}, {g.get('region', 'Unknown')}, {g.get('country', 'Unknown')}{Style.RESET_ALL}")
        
        if g.get('lat') and g.get('lon'):
            print(f"  └─ Coordinates: {Fore.WHITE}{g.get('lat')}, {g.get('lon')}{Style.RESET_ALL}")
        
        print(f"  └─ Timezone: {Fore.WHITE}{g.get('timezone', 'Unknown')}{Style.RESET_ALL}")
        print(f"  └─ ISP: {Fore.WHITE}{g.get('isp', 'Unknown')}{Style.RESET_ALL}")
        
        if g.get('org') != 'Unknown':
            print(f"  └─ Organization: {Fore.WHITE}{g.get('org')}{Style.RESET_ALL}")
        
        if g.get('as') != 'Unknown':
            print(f"  └─ ASN: {Fore.WHITE}{g.get('as')}{Style.RESET_ALL}")
        
        if g.get('asname') != 'Unknown':
            print(f"  └─ AS Name: {Fore.WHITE}{g.get('asname')}{Style.RESET_ALL}")
    
    dns = intel.get('dns', {})
    if dns and not dns.get('error'):
        print(f"\n{Fore.YELLOW}🔍 DNS Records:{Style.RESET_ALL}")
        if dns.get('has_reverse_dns'):
            print(f"  └─ Hostname: {Fore.WHITE}{dns.get('hostname', 'Unknown')}{Style.RESET_ALL}")
            if dns.get('ptr_records'):
                print(f"  └─ PTR Records: {Fore.WHITE}{', '.join(dns['ptr_records'][:3])}{Style.RESET_ALL}")
        else:
            print(f"  └─ {Fore.RED}No reverse DNS found{Style.RESET_ALL}")
    
    rep = intel.get('reputation', {})
    if rep and not rep.get('error'):
        print(f"\n{Fore.YELLOW}⚠️  Reputation Indicators:{Style.RESET_ALL}")
        
        inds = []
        if rep.get('is_cloud'):
            inds.append(f"{Fore.CYAN}☁️  Cloud Provider{Style.RESET_ALL}")
        if rep.get('is_hosting'):
            inds.append(f"{Fore.CYAN}🖥️  Hosting/Datacenter{Style.RESET_ALL}")
        if rep.get('is_vpn'):
            inds.append(f"{Fore.RED}🔒 VPN/Proxy Service{Style.RESET_ALL}")
        if rep.get('is_tor'):
            inds.append(f"{Fore.RED}🧅 Tor Exit Node{Style.RESET_ALL}")
        
        if inds:
            for ind in inds:
                print(f"  └─ {ind}")
        else:
            print(f"  └─ {Fore.GREEN}No special indicators{Style.RESET_ALL}")
        
        risk_sc = rep.get('risk_score', 0)
        if risk_sc > 30:
            risk_clr = Fore.RED
            risk_lbl = "HIGH"
        elif risk_sc > 10:
            risk_clr = Fore.YELLOW
            risk_lbl = "MEDIUM"
        else:
            risk_clr = Fore.GREEN
            risk_lbl = "LOW"
        
        print(f"  └─ Risk Score: {risk_clr}{risk_sc}/100 ({risk_lbl}){Style.RESET_ALL}")

def display_result(r):
    addr = r['ip']
    sc = r['total_hp_score']
    risk = r['risk_level']
    
    if risk >= 4:
        clr = Fore.RED
        icon = "🚫"
    elif risk == 3:
        clr = Fore.YELLOW
        icon = "⚠️ "
    elif risk == 2:
        clr = Fore.YELLOW
        icon = "⚡"
    else:
        clr = Fore.GREEN
        icon = "✓"
    
    print(f"\n{clr}{'═' * 60}{Style.RESET_ALL}")
    print(f"{clr}{icon}  {Style.BRIGHT}{addr}{Style.RESET_ALL} {clr}[Score: {sc} | Risk: {risk}/5]{Style.RESET_ALL}")
    print(f"{clr}{'─' * 60}{Style.RESET_ALL}")
    
    if not r['active']:
        print(f"  {Fore.RED}OFFLINE - Host not responding{Style.RESET_ALL}")
        return
    
    if 'intelligence' in r:
        display_intelligence(r['intelligence'])
    
    if r['ssh']:
        print(f"\n{Fore.CYAN}{Style.BRIGHT}🔐 SSH Services:{Style.RESET_ALL}")
        for pt, ssh in r['ssh'].items():
            print(f"{Fore.CYAN}  Port {pt}: {Fore.GREEN}ACTIVE{Style.RESET_ALL}")
            
            if ssh['banner']:
                bn = ssh['banner'][:70]
                print(f"    └─ Banner: {Fore.YELLOW}{bn}{Style.RESET_ALL}")
            
            if ssh.get('tcp_info', {}).get('avg_time'):
                avg_t = ssh['tcp_info']['avg_time']
                print(f"    └─ Avg Response: {Fore.YELLOW}{avg_t:.3f}s{Style.RESET_ALL}")
            
            if ssh['flags']:
                print(f"    └─ {Fore.RED}Suspicious Indicators:{Style.RESET_ALL}")
                for fl in ssh['flags']:
                    print(f"       • {Fore.RED}{fl}{Style.RESET_ALL}")
    
    v = r['verdict']
    vmap = {
        'HONEYPOT': f"{Fore.RED}{Style.BRIGHT}⛔ CONFIRMED HONEYPOT - DO NOT ENGAGE{Style.RESET_ALL}",
        'LIKELY_HONEYPOT': f"{Fore.RED}{Style.BRIGHT}🚨 LIKELY HONEYPOT - AVOID{Style.RESET_ALL}",
        'SUSPICIOUS': f"{Fore.YELLOW}⚠️  SUSPICIOUS - PROCEED WITH CAUTION{Style.RESET_ALL}",
        'CAUTION': f"{Fore.YELLOW}⚡ MINOR CONCERNS - BE CAREFUL{Style.RESET_ALL}",
        'CLEAN': f"{Fore.GREEN}✓ CLEAN - SAFE TO PROCEED{Style.RESET_ALL}",
        'OFFLINE': f"{Fore.RED}💤 OFFLINE{Style.RESET_ALL}"
    }
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'─' * 60}{Style.RESET_ALL}")
    print(f"{Style.BRIGHT}VERDICT:{Style.RESET_ALL} {vmap.get(v, v)}")
    print(f"{Fore.LIGHTCYAN_EX}{'─' * 60}{Style.RESET_ALL}")

def run_honeypot_analysis():
    os.system('cls' if os.name == 'nt' else 'clear')
    print_banner()
    
    fp = select_file()
    if not fp:
        input(Fore.CYAN + "\nPress Enter to continue...")
        return
    
    print(f"\n{Fore.GREEN}[✓] Loaded: {fp}{Style.RESET_ALL}")
    
    tgts = parse_targets(fp)
    print(f"{Fore.GREEN}[✓] Found {len(tgts)} targets with open ports{Style.RESET_ALL}")
    
    if not tgts:
        print(f"{Fore.YELLOW}[!] No targets found{Style.RESET_ALL}")
        input(Fore.CYAN + "\nPress Enter to continue...")
        return
    
    print()
    render_panel("SCAN CONFIG")
    print(f"  Targets: {Fore.YELLOW}{len(tgts)}{Style.RESET_ALL}")
    print(f"  Honeypot Detection: {Fore.GREEN}ACTIVE{Style.RESET_ALL}")
    print(f"  Intelligence Gathering: {Fore.GREEN}ENABLED{Style.RESET_ALL}")
    
    gather_intel = input(f"\n{Style.BRIGHT}Gather detailed intelligence (WHOIS, geo, etc.)? (Y/n): {Style.RESET_ALL}").strip().lower()
    gather_intel = gather_intel != 'n'
    
    if gather_intel:
        print(f"{Fore.YELLOW}[!] Intelligence gathering will take longer but provides detailed info{Style.RESET_ALL}")
    
    input(f"\n{Style.BRIGHT}Press ENTER to begin...{Style.RESET_ALL}")
    
    prober = NetworkProber(timeout=3)
    
    print()
    render_panel("SCANNING")
    print()
    
    all_res = []
    clean = []
    suspicious = []
    hpots = []
    offline = []
    
    tot = len(tgts)
    for idx, (addr, pts) in enumerate(tgts.items(), 1):
        show_progress(idx, tot, addr)
        
        res = prober.full_scan(addr, pts, gather_intel=gather_intel)
        all_res.append(res)
        
        if res['verdict'] == 'OFFLINE':
            offline.append(addr)
        elif res['risk_level'] >= 4:
            hpots.append(addr)
        elif res['risk_level'] == 3:
            suspicious.append(addr)
        else:
            clean.append(addr)
    
    print()
    
    print()
    render_panel("DETAILED RESULTS")
    
    for res in all_res:
        display_result(res)
        print()
    
    print()
    render_panel("SUMMARY")
    print(f"\n  {Fore.GREEN}✓ Clean:{Style.RESET_ALL} {Style.BRIGHT}{len(clean)}{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}⚠ Suspicious:{Style.RESET_ALL} {Style.BRIGHT}{len(suspicious)}{Style.RESET_ALL}")
    print(f"  {Fore.RED}🚫 Honeypots:{Style.RESET_ALL} {Style.BRIGHT}{len(hpots)}{Style.RESET_ALL}")
    print(f"  {Fore.RED}💤 Offline:{Style.RESET_ALL} {Style.BRIGHT}{len(offline)}{Style.RESET_ALL}")
    
    if clean:
        print(f"\n{Fore.GREEN}{Style.BRIGHT}SAFE TARGETS:{Style.RESET_ALL}")
        for addr in clean:
            res = next((r for r in all_res if r['ip'] == addr), None)
            if res and res.get('intelligence'):
                org = res['intelligence'].get('whois', {}).get('organization', 'Unknown')
                country = res['intelligence'].get('geolocation', {}).get('country', 'Unknown')
                print(f"  {Fore.GREEN}✓{Style.RESET_ALL} {addr:<15} [{org[:30]}] [{country}]")
            else:
                print(f"  {Fore.GREEN}✓{Style.RESET_ALL} {addr}")
    
    if hpots:
        print(f"\n{Fore.RED}{Style.BRIGHT}🚨 HONEYPOTS DETECTED:{Style.RESET_ALL}")
        for addr in hpots:
            res = next((r for r in all_res if r['ip'] == addr), None)
            if res and res.get('intelligence'):
                org = res['intelligence'].get('whois', {}).get('organization', 'Unknown')
                print(f"  {Fore.RED}🚫{Style.RESET_ALL} {addr:<15} [{org[:30]}]")
            else:
                print(f"  {Fore.RED}🚫{Style.RESET_ALL} {addr}")
    
    out = f"honeypot_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(out, 'w') as f:
        json.dump({
            'timestamp': datetime.now().isoformat(),
            'source': fp,
            'scanned': len(all_res),
            'intelligence_gathered': gather_intel,
            'clean': clean,
            'suspicious': suspicious,
            'honeypots': hpots,
            'offline': offline,
            'details': all_res
        }, f, indent=2)
    
    print(f"\n{Fore.GREEN}[✓] Full report saved: {out}{Style.RESET_ALL}\n")
    input(Fore.CYAN + "Press Enter to continue...")


def main():
    misc_opts = {"allow_public": False}
    
    os.system('cls' if os.name == 'nt' else 'clear')
    print_banner()

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print_banner()
        
        print()
        render_panel("MAIN MENU")
        print()
        opts = [
            ("1", "SSH Mass Scanner · Scan Public IPs for SSH"),
            ("2", "Scan SSH IPs OSINT"),
            ("3", "Settings & Configuration"),
            ("4", "Exit"),
        ]
        for k, lbl in opts:
            print(Fore.LIGHTCYAN_EX + Style.BRIGHT + f"  {k}. {lbl}" + Style.RESET_ALL)
        print()
        
        st = "ENABLED" if misc_opts.get("allow_public") else "DISABLED"
        st_clr = Fore.GREEN if misc_opts.get("allow_public") else Fore.RED
        print(Fore.LIGHTCYAN_EX + "─" * 65 + Style.RESET_ALL)
        print(f"{Fore.LIGHTCYAN_EX}Public IP Scanning:{Style.RESET_ALL} {st_clr}{st}{Style.RESET_ALL}")
        print(Fore.LIGHTCYAN_EX + "─" * 65 + Style.RESET_ALL)
        print()
        
        choice = input(Fore.MAGENTA + "➤ Select option: " + Style.RESET_ALL).strip()

        if choice == "1":
            os.system('cls' if os.name == 'nt' else 'clear')
            print_banner()
            print()
            render_panel("SSH MASS SCANNER · PUBLIC IP SWEEP")
            
            if not misc_opts.get("allow_public"):
                print(Fore.YELLOW + "\n⚠  WARNING: Public IP scanning requires authorization!")
                print(Fore.YELLOW + "Only scan networks you own or have permission to test." + Style.RESET_ALL)
                confirm = input(Fore.RED + "\nEnable public scanning and proceed? (y/N): " + Style.RESET_ALL).strip().lower()
                if confirm == "y":
                    misc_opts["allow_public"] = True
                    print(Fore.GREEN + "✓ Public scanning enabled" + Style.RESET_ALL)
                else:
                    print(Fore.YELLOW + "✗ Scan aborted." + Style.RESET_ALL)
                    input(Fore.CYAN + "\nPress Enter to continue..." + Style.RESET_ALL)
                    continue
            
            print(Fore.CYAN + "\nScan Configuration:")
            print(Fore.WHITE + "  • Target: Random public IPs (auto-generated)")
            print(Fore.WHITE + "  • Ports: SSH (22, 2222, 2200, 22222)")
            print(Fore.WHITE + "  • Protocol: TCP only")
            print(Fore.WHITE + "  • Scanner: RustScan (if available) or Python fallback" + Style.RESET_ALL)
            
            batch_sz_inp = input(Fore.MAGENTA + "\n➤ IPs per batch (default: 100): " + Style.RESET_ALL).strip()
            try:
                batch_sz = int(batch_sz_inp) if batch_sz_inp else 100
                if batch_sz <= 0 or batch_sz > 1000:
                    print(Fore.RED + "[!] Batch size must be 1-1000. Using default 100." + Style.RESET_ALL)
                    batch_sz = 100
            except ValueError:
                print(Fore.RED + "[!] Invalid batch size. Using default 100." + Style.RESET_ALL)
                batch_sz = 100
            
            out_file = input(Fore.MAGENTA + "➤ Output file (default: xro_results.json): " + Style.RESET_ALL).strip()
            if not out_file:
                out_file = "xro_results.json"
            
            print(Fore.GREEN + f"\n✓ Starting CONTINUOUS scan with {batch_sz} IPs per batch..." + Style.RESET_ALL)
            perform_mass_scan(1.5, out_file, misc_opts, batch_size=batch_sz)
            
        elif choice == "2":
            run_honeypot_analysis()
            
        elif choice == "3":
            os.system('cls' if os.name == 'nt' else 'clear')
            print_banner()
            print()
            render_panel("SETTINGS")
            print()
            cur_st = "ENABLED" if misc_opts.get("allow_public") else "DISABLED"
            st_clr = Fore.GREEN if misc_opts.get("allow_public") else Fore.RED
            print(Fore.LIGHTCYAN_EX + Style.BRIGHT + "  1. Public IP Scanning:" + Style.RESET_ALL + f" {st_clr}{cur_st}{Style.RESET_ALL}")
            print()
            print(Fore.LIGHTCYAN_EX + Style.BRIGHT + "  T. Toggle public IP scanning" + Style.RESET_ALL)
            print(Fore.LIGHTCYAN_EX + Style.BRIGHT + "  B. Back to main menu" + Style.RESET_ALL)
            print()
            
            set_choice = input(Fore.MAGENTA + "➤ Choose an option: " + Style.RESET_ALL).strip().lower()
            
            if set_choice == "t":
                misc_opts["allow_public"] = not misc_opts.get("allow_public")
                new_st = "ENABLED" if misc_opts["allow_public"] else "DISABLED"
                print(Fore.GREEN + f"\n✓ Public IP scanning {new_st}" + Style.RESET_ALL)
                input(Fore.CYAN + "\nPress Enter to continue..." + Style.RESET_ALL)
            elif set_choice == "b":
                continue
            else:
                print(Fore.RED + "[!] Invalid choice." + Style.RESET_ALL)
                input(Fore.CYAN + "\nPress Enter to continue..." + Style.RESET_ALL)
                
        elif choice == "4":
            print(Fore.GREEN + "\nExiting XRO Network Scanner..." + Style.RESET_ALL)
            print(Fore.CYAN + "Thank you for using XRO!" + Style.RESET_ALL)
            break
            
        else:
            print(Fore.RED + "[!] Invalid choice. Please select 1-4." + Style.RESET_ALL)
            input(Fore.CYAN + "\nPress Enter to continue..." + Style.RESET_ALL)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.RED}[!] Program interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] An error occurred: {e}{Style.RESET_ALL}")
        sys.exit(1)