"""
This module contains the regex-based detection rules
and rule functions used against normalized logs in detector.py
"""

import re
import os

# --- Regex patterns ---
failed_login_pattern = re.compile(
    r"(failed|invalid).*login", re.IGNORECASE
)

suspicious_process_pattern = re.compile(
    r"(powershell\.exe|cmd\.exe|wscript\.exe).*?-enc", re.IGNORECASE
)

base64_pattern = re.compile(
    r"(?:[A-Za-z0-9+/]{20,}={0,2})"
)

web_sqli_pattern = re.compile(
    r"(\bor\b|\band\b).*(=|<|>).*(\b\d\b|'|\"|\%)", re.IGNORECASE
)

web_rce_pattern = re.compile(
    r"(;|\|\||&&)\s*(wget|curl|bash|sh)", re.IGNORECASE
)

web_traversal_pattern = re.compile(
    r"\.\./\.\./|\.\.\\\.\.\\"
)

# --- Rule functions ---

def failed_login(event):
    return any(
        failed_login_pattern.search(str(value))
        for value in (event.normalized.get("message"), event.normalized.get("description"))
        if value
    )

def suspicious_process(event):
    """Detects suspicious encoded commands in common LOLBins."""
    return any(
        suspicious_process_pattern.search(value)
        for value in (event.normalized.get("parent_process"), 
                      event.normalized.get("process_name"), 
                      event.normalized.get("command_line"))
        if value
    )

def suspicious_binary(event):
    process_path = event.normalized.get("process_name", "").lower()
    process_name = os.path.basename(process_path)

    whitelist = ["explorer.exe", "cmd.exe", "powershell.exe", "svchost.exe"]
    
    if not process_name:
        return False

    if process_name.endswith(".exe") and process_name not in whitelist:
        #if parent_process in ["cmd.exe", "powershell.exe", "explorer.exe"]:
            return True
    
    return False



def base64_command(event):
    return base64_pattern.search(event.normalized.get("command_line") or "") is not None

def rare_external_ip(event):
    """Very simple heuristic: External (non-RFC1918) IPs."""
    if not event.normalized.get("src_ip"):
        return False
    
    # RFC1918 private IP ranges
    private_ranges = ("10.", "172.16.", "192.168.")
    
    return not event.normalized.get("src_ip").startswith(private_ranges)

def web_attack(event):
    
    request = event.normalized.get("request") or ""
    url = event.normalized.get("url") or ""

    return (
        web_sqli_pattern.search(request or url)
        or web_rce_pattern.search(request or url)
        or web_traversal_pattern.search(request or url)
    )

