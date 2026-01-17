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
- ✅ **Scan a WordPress site**
python3 scanner.py https://example.com --scan
- ✅ **Check for updates**
python3 scanner.py --check-update
- ✅ **Update to latest version**
python3 scanner.py --update
- ✅ **Setup environment**
python3 scanner.py --setup
- ✅ **Show help**
python3 scanner.py --help

## 📋 Usage Examples ##
- ✅ **Simple scan**
python3 scanner.py https://target.com --scan
- ✅ **Full scan with exploitation**
python3 scanner.py https://target.com --full
- ✅ **Scan from file (multiple targets)**
python3 scanner.py -f targets.txt

### advance features ###
- ✅ **Exploit specific plugin**
python3 scanner.py https://target.com --exploit --plugin "contact-form-7"
- ✅ **Brute force attack**
python3 scanner.py https://target.com --brute --username admin
- ✅ **Shell upload test**
python3 scanner.py https://target.com --upload-test
- ✅ **WAF bypass mode**
python3 scanner.py https://target.com --waf-bypass

## ⚠️ Disclaimer

**This tool is for educational purposes and authorized penetration testing only.**

🚫 **DO NOT use this tool against websites you do not own or have explicit permission to test.**

🔒 **Unauthorized access to computer systems is illegal and punishable by law.**

## 📄 License

MIT License - see [LICENSE](https://github.com/BCEVM/WPScanner/blob/main/LICENSE.txt) file for details.

## 👥 Author

**BCEVM - Hacktivist Indonesia**

- GitHub: [@BCEVM](https://github.com/BCEVM)
- Repository: [WPScanner](https://github.com/BCEVM/WPScanner)
- Issues: [Report Bug](https://github.com/BCEVM/WPScanner/issues)

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## ⭐ Support

If you find this tool useful, please give it a ⭐ on GitHub!
