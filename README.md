# 🔥 BCEVM WordPress Security Scanner

Advanced WordPress security scanner with auto-update from GitHub.

![Version](https://img.shields.io/badge/Version-6.0.0-blue)
![Python](https://img.shields.io/badge/Python-3.6%2B-green)
![License](https://img.shields.io/badge/License-MIT-orange)

## 🚀 Features

- ✅ **Auto-update** from GitHub
- ✅ **Exploit database** with 50+ vulnerabilities
- ✅ **WAF bypass** techniques
- ✅ **Multi-threaded** scanning
- ✅ **Compact reporting**
- ✅ **Plugin enumeration**
- ✅ **User enumeration**
- ✅ **Brute force detection**
- ✅ **Shell upload** capabilities

## 📦 Installation

### Method 1: Direct Download
```bash
wget https://raw.githubusercontent.com/BCEVM/WPScanner/main/scanner.py
chmod +x scanner.py

git clone https://github.com/BCEVM/WPScanner.git
cd WPScanner
pip install -r requirements.txt

```
## 🎯 Quick Start ##  
----------------------------
# Scan a WordPress site
python3 scanner.py https://example.com --scan

# Check for updates
python3 scanner.py --check-update

# Update to latest version
python3 scanner.py --update

# Setup environment
python3 scanner.py --setup

# Show help
python3 scanner.py --help
