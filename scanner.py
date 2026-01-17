#!/usr/bin/env python3
"""
BCEVM – WordPress Security Scanner & Exploiter v6.0
WITH AUTO-UPDATE FROM GITHUB
Tools by BCEVM - Hacktivist Indonesia
GitHub: https://github.com/BCEVM/WPScanner
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
import shutil
import zipfile
import io
from urllib.parse import urlparse, urlencode, quote, unquote
from datetime import datetime
from colorama import init, Fore, Style, Back
import concurrent.futures
import base64
import subprocess
import tempfile

requests.packages.urllib3.disable_warnings()
init(autoreset=True)

# ==================== GITHUB CONFIGURATION ====================
GITHUB_USER = "BCEVM"
GITHUB_REPO = "WPScanner"
GITHUB_API = f"https://api.github.com/repos/{GITHUB_USER}/{GITHUB_REPO}"
GITHUB_RAW = f"https://raw.githubusercontent.com/{GITHUB_USER}/{GITHUB_REPO}/main"
GITHUB_ZIP = f"https://github.com/{GITHUB_USER}/{GITHUB_REPO}/archive/refs/heads/main.zip"
LATEST_RELEASE_API = f"{GITHUB_API}/releases/latest"
# ==============================================================

BANNER = f"""
{Fore.RED}╔══════════════════════════════════════════════════════════════╗
║{Fore.YELLOW}    ██████╗  ██████╗███████╗██╗   ██╗███╗   ███╗    {Fore.RED}       ║
║{Fore.YELLOW}    ██╔══██╗██╔════╝██╔════╝██║   ██║████╗ ████║    {Fore.RED}       ║
║{Fore.YELLOW}    ██████╔╝██║     █████╗  ██║   ██║██╔████╔██║    {Fore.RED}       ║
║{Fore.YELLOW}    ██╔══██╗██║     ██╔══╝  ██║   ██║██║╚██╔╝██║    {Fore.RED}       ║
║{Fore.YELLOW}    ██████╔╝╚██████╗███████╗╚██████╔╝██║ ╚═╝ ██║    {Fore.RED}       ║
║{Fore.CYAN}        WordPress Security Scanner v6.0            {Fore.RED}║
║{Fore.WHITE}            GitHub: github.com/BCEVM/WPScanner          {Fore.RED}║
║{Fore.GREEN}              Tools by BCEVM - Hacktivist Indonesia      {Fore.RED}║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

# LOCAL CONFIG
CONFIG_FILE = "bcevm_config.json"
VERSION_FILE = "version.txt"
BACKUP_DIR = "backups"
LOG_DIR = "logs"
REPORT_DIR = "reports"
EXPLOIT_DIR = "exploits"

class GitHubUpdater:
    """Handle GitHub updates and synchronization for BCEVM/WPScanner"""
    
    @staticmethod
    def check_updates(current_version="6.0.0"):
        """Check for updates on GitHub"""
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Checking GitHub for updates...")
        print(f"  Repository: {GITHUB_USER}/{GITHUB_REPO}")
        
        try:
            response = requests.get(LATEST_RELEASE_API, timeout=10)
            if response.status_code == 200:
                data = response.json()
                latest_version = data.get("tag_name", "v6.0.0").lstrip('v')
                release_name = data.get("name", "Latest Release")
                
                print(f"  Current Version: {current_version}")
                print(f"  Latest Release: {release_name} (v{latest_version})")
                
                # Compare versions
                if GitHubUpdater.compare_versions(current_version, latest_version) < 0:
                    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} New update available!")
                    return {
                        "update": True,
                        "current": current_version,
                        "latest": latest_version,
                        "release_name": release_name,
                        "release_url": data.get("html_url", f"https://github.com/{GITHUB_USER}/{GITHUB_REPO}/releases"),
                        "release_notes": data.get("body", "Bug fixes and improvements"),
                        "download_url": data.get("zipball_url", "")
                    }
                else:
                    print(f"{Fore.GREEN}[✓]{Style.RESET_ALL} You have the latest version")
                    return {"update": False, "current": current_version, "latest": latest_version}
            elif response.status_code == 404:
                # No releases yet, check main branch
                print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} No releases found, checking main branch...")
                return GitHubUpdater.check_main_branch(current_version)
                
        except Exception as e:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} Update check failed: {str(e)[:50]}")
        
        return {"update": False}
    
    @staticmethod
    def check_main_branch(current_version):
        """Check main branch for updates"""
        try:
            # Get main branch info
            branch_url = f"{GITHUB_API}/git/refs/heads/main"
            response = requests.get(branch_url, timeout=10)
            
            if response.status_code == 200:
                branch_data = response.json()
                latest_commit = branch_data["object"]["sha"][:7]
                
                print(f"  Main branch commit: {latest_commit}")
                
                # Check if we need to update from main branch
                # (Simple check based on local modified time)
                local_modified = os.path.getmtime(__file__) if os.path.exists(__file__) else 0
                # We'll assume update available if user wants fresh copy
                
                return {
                    "update": True,
                    "current": current_version,
                    "latest": f"main-{latest_commit}",
                    "release_name": "Main Branch",
                    "release_url": f"https://github.com/{GITHUB_USER}/{GITHUB_REPO}",
                    "release_notes": "Latest development version from main branch"
                }
                
        except Exception as e:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} Branch check failed: {str(e)[:50]}")
        
        return {"update": False}
    
    @staticmethod
    def compare_versions(v1, v2):
        """Compare version strings"""
        def normalize(v):
            # Extract numbers from version string
            parts = []
            for part in re.findall(r'\d+|\D+', v):
                if part.isdigit():
                    parts.append(int(part))
                else:
                    parts.append(part)
            return parts
        
        v1_norm = normalize(v1)
        v2_norm = normalize(v2)
        
        return (v1_norm > v2_norm) - (v1_norm < v2_norm)
    
    @staticmethod
    def backup_current_files():
        """Create backup of current files before update"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(BACKUP_DIR, f"backup_v6.0_{timestamp}")
        
        os.makedirs(BACKUP_DIR, exist_ok=True)
        os.makedirs(backup_path, exist_ok=True)
        
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Creating backup at: {backup_path}")
        
        # Files to backup
        backup_files = [
            "*.py", "*.txt", "*.json", "*.md",
            "requirements.txt", "bcevm_config.json"
        ]
        
        import glob
        files_copied = 0
        
        for pattern in backup_files:
            for file in glob.glob(pattern):
                try:
                    if os.path.isfile(file):
                        shutil.copy2(file, os.path.join(backup_path, file))
                        files_copied += 1
                except Exception as e:
                    print(f"  Failed to backup {file}: {str(e)[:30]}")
        
        # Backup directories
        backup_dirs = ["exploits", "data"]
        for dir_name in backup_dirs:
            if os.path.exists(dir_name):
                try:
                    shutil.copytree(dir_name, os.path.join(backup_path, dir_name))
                    files_copied += 1
                except:
                    pass
        
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Backup completed: {files_copied} files/directories")
        return backup_path
    
    @staticmethod
    def download_latest_version():
        """Download latest version from GitHub"""
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Downloading latest version from GitHub...")
        
        try:
            # Create temp directory
            temp_dir = tempfile.mkdtemp(prefix="bcevm_update_")
            zip_path = os.path.join(temp_dir, "latest.zip")
            
            # Download from GitHub
            print(f"  Downloading: {GITHUB_ZIP}")
            response = requests.get(GITHUB_ZIP, stream=True, timeout=30)
            
            if response.status_code == 200:
                total_size = int(response.headers.get('content-length', 0))
                downloaded = 0
                
                with open(zip_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            downloaded += len(chunk)
                            
                            # Progress indicator
                            if total_size > 0:
                                percent = (downloaded / total_size) * 100
                                sys.stdout.write(f"\r  Progress: {percent:.1f}% ({downloaded/1024:.0f}KB/{total_size/1024:.0f}KB)")
                                sys.stdout.flush()
                
                print(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} Download completed: {os.path.getsize(zip_path)/1024:.0f}KB")
                return zip_path
            else:
                print(f"{Fore.RED}[-]{Style.RESET_ALL} Download failed: HTTP {response.status_code}")
                
        except Exception as e:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} Download error: {str(e)}")
        
        return None
    
    @staticmethod
    def extract_update(zip_path):
        """Extract downloaded update"""
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Extracting update...")
        
        try:
            # Create extraction directory
            extract_dir = tempfile.mkdtemp(prefix="bcevm_extract_")
            
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                # Get the root folder name (usually "WPScanner-main")
                members = zip_ref.namelist()
                if members:
                    root_folder = members[0].split('/')[0]
                    
                # Extract all files
                zip_ref.extractall(extract_dir)
                
                # Path to extracted content
                source_dir = os.path.join(extract_dir, root_folder)
                
                if os.path.exists(source_dir):
                    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Extracted to: {source_dir}")
                    return source_dir
                else:
                    print(f"{Fore.RED}[-]{Style.RESET_ALL} Extraction failed: root folder not found")
                    
        except Exception as e:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} Extraction error: {str(e)}")
        
        return None
    
    @staticmethod
    def apply_update(source_dir):
        """Apply the update by copying files"""
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Applying update...")
        
        try:
            files_updated = 0
            files_skipped = 0
            
            # Walk through source directory
            for root, dirs, files in os.walk(source_dir):
                # Calculate relative path
                rel_path = os.path.relpath(root, source_dir)
                if rel_path == '.':
                    rel_path = ''
                
                # Create destination directories
                for dir_name in dirs:
                    dest_dir = os.path.join(rel_path, dir_name) if rel_path else dir_name
                    os.makedirs(dest_dir, exist_ok=True)
                
                # Copy files
                for file_name in files:
                    src_file = os.path.join(root, file_name)
                    
                    # Skip certain files
                    if file_name.endswith('.gitignore') or file_name == '.git':
                        continue
                    
                    dest_file = os.path.join(rel_path, file_name) if rel_path else file_name
                    
                    try:
                        # Copy file, overwrite if exists
                        shutil.copy2(src_file, dest_file)
                        files_updated += 1
                        print(f"  Updated: {dest_file}")
                        
                    except Exception as e:
                        print(f"  Failed to update {dest_file}: {str(e)[:30]}")
                        files_skipped += 1
            
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Update applied: {files_updated} files updated, {files_skipped} skipped")
            return True
            
        except Exception as e:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} Update error: {str(e)}")
        
        return False
    
    @staticmethod
    def update_self():
        """Main update function"""
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} ===== BCEVM WPScanner Update Process =====")
        
        # Step 1: Backup
        backup_path = GitHubUpdater.backup_current_files()
        
        # Step 2: Download
        zip_path = GitHubUpdater.download_latest_version()
        if not zip_path:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} Update failed at download stage")
            return False
        
        # Step 3: Extract
        source_dir = GitHubUpdater.extract_update(zip_path)
        if not source_dir:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} Update failed at extraction stage")
            return False
        
        # Step 4: Apply
        success = GitHubUpdater.apply_update(source_dir)
        
        # Step 5: Cleanup
        try:
            # Remove temp files
            temp_dir = os.path.dirname(zip_path)
            shutil.rmtree(temp_dir, ignore_errors=True)
            
            extract_base = os.path.dirname(source_dir)
            shutil.rmtree(extract_base, ignore_errors=True)
            
        except:
            pass
        
        if success:
            print(f"\n{Fore.GREEN}[✓]{Style.RESET_ALL} UPDATE COMPLETED SUCCESSFULLY!")
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Backup saved at: {backup_path}")
            print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Please restart the tool to use new features")
            return True
        
        print(f"\n{Fore.RED}[-]{Style.RESET_ALL} Update failed")
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Restore backup from: {backup_path}")
        return False

class ConfigManager:
    """Manage tool configuration"""
    
    DEFAULT_CONFIG = {
        "version": "6.0.0",
        "author": "BCEVM - Hacktivist Indonesia",
        "github_repo": "BCEVM/WPScanner",
        "github_url": "https://github.com/BCEVM/WPScanner",
        "auto_update": True,
        "last_update_check": None,
        "proxy": None,
        "timeout": 30,
        "threads": 5,
        "user_agent": "BCEVM-WPScanner/6.0",
        "log_level": "INFO",
        "report_dir": "reports",
        "exploit_db_url": f"https://raw.githubusercontent.com/{GITHUB_USER}/{GITHUB_REPO}/main/exploits/exploit_db.json"
    }
    
    @staticmethod
    def load_config():
        """Load configuration from file"""
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                
                # Merge with defaults for missing keys
                for key, value in ConfigManager.DEFAULT_CONFIG.items():
                    if key not in config:
                        config[key] = value
                
                return config
            except Exception as e:
                print(f"{Fore.RED}[-]{Style.RESET_ALL} Config load error: {str(e)[:50]}")
        
        # Return defaults and save
        ConfigManager.save_config(ConfigManager.DEFAULT_CONFIG)
        return ConfigManager.DEFAULT_CONFIG.copy()
    
    @staticmethod
    def save_config(config):
        """Save configuration to file"""
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=2, sort_keys=True)
            return True
        except Exception as e:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} Config save error: {str(e)[:50]}")
            return False
    
    @staticmethod
    def update_config(key, value):
        """Update single config value"""
        config = ConfigManager.load_config()
        config[key] = value
        return ConfigManager.save_config(config)
    
    @staticmethod
    def get_version():
        """Get current version"""
        config = ConfigManager.load_config()
        return config.get("version", "6.0.0")

class WPScanner:
    """Main WordPress Scanner"""
    
    def __init__(self, target=None, config=None):
        self.target = target
        self.config = config or ConfigManager.load_config()
        self.session = requests.Session()
        self.session.verify = False
        
        # Setup session
        self.session.headers.update({
            "User-Agent": self.config.get("user_agent", "BCEVM-WPScanner/6.0"),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive"
        })
        
        if self.config.get("proxy"):
            self.session.proxies = {
                "http": self.config["proxy"],
                "https": self.config["proxy"]
            }
        
        self.timeout = self.config.get("timeout", 30)
        self.results = {}
    
    def scan(self):
        """Basic WordPress scan"""
        if not self.target:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} No target specified")
            return None
        
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} Scanning: {self.target}")
        
        try:
            response = self.session.get(self.target, timeout=self.timeout)
            
            if response.status_code == 200:
                content = response.text
                
                # Check WordPress
                wp_indicators = [
                    'wp-content', 'wp-includes', 'wp-json',
                    'wordpress', 'WordPress', 'wp-admin'
                ]
                
                wp_detected = any(indicator in content.lower() for indicator in wp_indicators)
                
                self.results = {
                    "target": self.target,
                    "status": response.status_code,
                    "wordpress": wp_detected,
                    "title": self.extract_title(content),
                    "version": self.extract_version(content),
                    "plugins": self.extract_plugins(content),
                    "theme": self.extract_theme(content),
                    "users": [],
                    "vulnerabilities": []
                }
                
                self.display_results()
                return self.results
            else:
                print(f"{Fore.RED}[-]{Style.RESET_ALL} Target returned status: {response.status_code}")
                
        except Exception as e:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} Scan error: {str(e)}")
        
        return None
    
    def extract_title(self, content):
        """Extract page title"""
        match = re.search(r'<title>(.*?)</title>', content, re.IGNORECASE)
        return match.group(1) if match else "No title"
    
    def extract_version(self, content):
        """Extract WordPress version"""
        patterns = [
            r'content="WordPress\s+([\d.]+)"',
            r'generator>https://wordpress\.org/\?v=([\d.]+)<',
            r'wp-embed\.js\?ver=([\d.]+)',
            r'Version\s+([\d.]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return "Unknown"
    
    def extract_plugins(self, content):
        """Extract plugins from HTML"""
        plugins = set()
        pattern = r'/wp-content/plugins/([^/]+)/'
        
        matches = re.findall(pattern, content, re.IGNORECASE)
        for match in matches:
            plugins.add(match.lower())
        
        return sorted(list(plugins))
    
    def extract_theme(self, content):
        """Extract theme from HTML"""
        pattern = r'/wp-content/themes/([^/]+)/'
        match = re.search(pattern, content, re.IGNORECASE)
        
        if match:
            return match.group(1).lower()
        
        return "Unknown"
    
    def display_results(self):
        """Display scan results"""
        print(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} SCAN RESULTS:")
        print(f"  Target: {self.results['target']}")
        print(f"  WordPress: {'YES' if self.results['wordpress'] else 'NO'}")
        print(f"  Version: {self.results['version']}")
        print(f"  Theme: {self.results['theme']}")
        print(f"  Plugins ({len(self.results['plugins'])}):")
        
        for plugin in self.results['plugins'][:10]:  # Show first 10
            print(f"    - {plugin}")
        
        if len(self.results['plugins']) > 10:
            print(f"    ... and {len(self.results['plugins']) - 10} more")
    
    def generate_report(self):
        """Generate scan report"""
        if not self.results:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} No scan results to report")
            return None
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"scan_{self.target.replace('://', '_').replace('/', '_')}_{timestamp}.txt"
        
        os.makedirs(REPORT_DIR, exist_ok=True)
        report_path = os.path.join(REPORT_DIR, report_file)
        
        report = [
            "=" * 70,
            "BCEVM WordPress Security Scan Report",
            f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Tool Version: {self.config.get('version', '6.0.0')}",
            f"GitHub: {self.config.get('github_url', 'https://github.com/BCEVM/WPScanner')}",
            "=" * 70,
            "",
            f"Target URL: {self.results['target']}",
            f"Status Code: {self.results.get('status', 'N/A')}",
            f"Page Title: {self.results.get('title', 'N/A')}",
            f"WordPress Detected: {'Yes' if self.results['wordpress'] else 'No'}",
            f"WordPress Version: {self.results.get('version', 'Unknown')}",
            f"Theme: {self.results.get('theme', 'Unknown')}",
            "",
            f"Plugins Found ({len(self.results.get('plugins', []))}):",
        ]
        
        for plugin in self.results.get('plugins', []):
            report.append(f"  • {plugin}")
        
        report.extend([
            "",
            "=" * 70,
            "Generated by BCEVM WPScanner",
            "https://github.com/BCEVM/WPScanner",
            "For authorized security testing only",
            "=" * 70
        ])
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(report))
        
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Report saved: {report_path}")
        return report_path

def setup_environment():
    """Setup required directories and files"""
    directories = [BACKUP_DIR, LOG_DIR, REPORT_DIR, EXPLOIT_DIR, "data"]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Created directory: {directory}")
    
    # Create initial config if not exists
    if not os.path.exists(CONFIG_FILE):
        config = ConfigManager.DEFAULT_CONFIG.copy()
        config["first_run"] = datetime.now().isoformat()
        config["install_id"] = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        
        ConfigManager.save_config(config)
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Configuration file created: {CONFIG_FILE}")
    
    # Create version file
    config = ConfigManager.load_config()
    with open(VERSION_FILE, 'w') as f:
        f.write(config.get("version", "6.0.0"))
    
    # Create README if not exists - SIMPLE VERSION
    if not os.path.exists("README.md"):
        readme_lines = [
            "# BCEVM WordPress Security Scanner",
            "",
            "Advanced WordPress security scanner with auto-update from GitHub.",
            "",
            "## Features",
            f"- Auto-update from GitHub (github.com/{GITHUB_USER}/{GITHUB_REPO})",
            "- WordPress vulnerability detection",
            "- Plugin enumeration",
            "- Report generation",
            "- WAF bypass techniques",
            "",
            "## Quick Start",
            "```bash",
            "# Scan a target",
            "python3 scanner.py https://example.com --scan",
            "",
            "# Check for updates",
            "python3 scanner.py --check-update",
            "",
            "# Update to latest version",
            "python3 scanner.py --update",
            "",
            "# Setup environment",
            "python3 scanner.py --setup",
            "```",
            "",
            "## GitHub Repository",
            f"- URL: https://github.com/{GITHUB_USER}/{GITHUB_REPO}",
            f"- Issues: https://github.com/{GITHUB_USER}/{GITHUB_REPO}/issues",
            f"- Releases: https://github.com/{GITHUB_USER}/{GITHUB_REPO}/releases",
            "",
            "## Configuration",
            f"Edit `{CONFIG_FILE}` to customize settings.",
            "",
            "## Requirements",
            "- Python 3.6+",
            "- requests library",
            "",
            "## Disclaimer",
            "This tool is for educational purposes and authorized penetration testing only.",
            "Unauthorized use against systems you don't own is illegal.",
            "",
            "## License",
            "MIT License",
            "",
            "## Author",
            "BCEVM - Hacktivist Indonesia"
        ]
        
        with open("README.md", 'w') as f:
            f.write("\n".join(readme_lines))
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} README.md created")
    
    # Create requirements.txt
    if not os.path.exists("requirements.txt"):
        requirements = """requests>=2.31.0
colorama>=0.4.6
urllib3>=1.26.0
"""
        with open("requirements.txt", 'w') as f:
            f.write(requirements)
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} requirements.txt created")
    
    print(f"\n{Fore.GREEN}[✓]{Style.RESET_ALL} Environment setup completed")
    return True
