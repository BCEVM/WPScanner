# config.py
# WPScan API Configuration
WPSAN_API_TOKEN = "YOUR_API_KEY_HERE"  # Daftar di https://wpscan.com/api
WPSAN_API_URL = "https://wpscan.com/api/v3"

# File paths
EXPLOIT_DB_PATH = "exploits/exploit_db.json"
VULNERABLE_TARGETS_FILE = "vulnerable_targets.json"
REPORTS_DIR = "reports"

# Scan settings
TIMEOUT = 25
THREADS = 5
MAX_RETRIES = 3
RATE_LIMIT_DELAY = 1

# Notification settings
ENABLE_TELEGRAM = False
TELEGRAM_BOT_TOKEN = ""
TELEGRAM_CHAT_ID = ""

# Malware signatures
MALWARE_SIGNATURES = [
    "base64_decode",
    "eval(", "eval (",
    "gzinflate",
    "str_rot13",
    "system(", "system (",
    "shell_exec(", "shell_exec (",
    "exec(", "exec (",
    "passthru(", "passthru (",
    "popen(", "popen (",
    "proc_open(", "proc_open (",
    "assert(", "assert (",
    "create_function(",
    "include_once(", "include_once (",
    "require_once(", "require_once (",
    "<?php eval", "<?php system",
    "wget", "curl", "chmod", "chown"
]

# WAF Bypass settings
ENABLE_WAF_BYPASS = True
WAF_BYPASS_TECHNIQUES = ["headers", "delays", "encoding", "split_payloads"]
WAF_BYPASS_HEADERS = {
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
    "X-Forwarded-Scheme": "http",
    "X-Original-URL": "/",
    "X-Rewrite-URL": "/"
}
