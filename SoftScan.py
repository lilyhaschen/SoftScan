# 🐑 SoftScan: Vulnerability Scanner with Lamb Energy ✨
# Created by Lily

import re
import json
import socket
import argparse
import platform
from datetime import datetime
from pathlib import Path

SCAN_REPORT = Path("softscan_report.json")
COMMON_VULNERABILITIES = [
    {"pattern": r"<script>.*?</script>", "vuln": "XSS Detected", "severity": "High"},
    {"pattern": r"SELECT .* FROM .* WHERE .* = .*", "vuln": "Possible SQL Injection", "severity": "High"},
    {"pattern": r"admin[=:]\w+", "vuln": "Credential Leak", "severity": "Medium"},
    {"pattern": r"password[=:]\w+", "vuln": "Plaintext Password Found", "severity": "Critical"},
    {"pattern": r"href=\"http://", "vuln": "Insecure HTTP Link", "severity": "Low"},
    {"pattern": r"document\.cookie", "vuln": "Cookie Access in JS", "severity": "Medium"},
    {"pattern": r"system\(|popen\(|os\.system", "vuln": "Command Execution Risk", "severity": "Critical"},
    {"pattern": r"/bin/sh|/bin/bash", "vuln": "Shell Access Detected", "severity": "High"}
]

ASCII_LAMB = r"""
⠀⠀⠀              ◜ ͡   ͡   ◝ 
　               ૮ ﾉ ྀི 𓏼 ˊ͈   ˔  )  ··﹖
　   ╭◜◝ ͡  ʿʿ         𝜗𝜚 ˒　　　　　　
　  ૮'       　　　     ꒱ 　
　　 )　ﾉ,,_、  ﾉヽ) 　 
　　し'し'　l ﾉ     ,  SoftScan is awake and sniffing vulnerabilities.
"""

# (´･(00)･｀) Load Lamb Logic

def scan_text(text):
    results = []
    timestamp = datetime.utcnow().isoformat()
    for vuln in COMMON_VULNERABILITIES:
        if re.search(vuln["pattern"], text, re.IGNORECASE):
            results.append({
                "vulnerability": vuln["vuln"],
                "pattern": vuln["pattern"],
                "severity": vuln["severity"],
                "timestamp": timestamp,
                "host": socket.gethostname(),
                "os": platform.system(),
                "input": text,
                "recommendation": generate_recommendation(vuln["vuln"])
            })
    return results

# ૮₍ ´• ˕ •` ₎ა Security Advice

def generate_recommendation(vuln_name):
    advice = {
        "XSS Detected": "Sanitize input and use Content Security Policy (CSP).",
        "Possible SQL Injection": "Use parameterized queries and ORM frameworks.",
        "Credential Leak": "Avoid hardcoded credentials, use secrets management.",
        "Plaintext Password Found": "Store passwords using strong hashing (e.g., bcrypt).",
        "Insecure HTTP Link": "Upgrade to HTTPS and use secure headers.",
        "Cookie Access in JS": "Set HttpOnly flag on cookies.",
        "Command Execution Risk": "Avoid executing raw input. Use safe libraries.",
        "Shell Access Detected": "Avoid shell commands from user input."
    }
    return advice.get(vuln_name, "Review security best practices for this pattern.")

# 🧸 Save the fluff

def save_report(results):
    if not results:
        print("(｡•́︿•̀｡) No vulnerabilities found. Stay fluffy and safe.")
        return

    if SCAN_REPORT.exists():
        with open(SCAN_REPORT, 'r') as f:
            existing = json.load(f)
    else:
        existing = []

    existing.extend(results)
    with open(SCAN_REPORT, 'w') as f:
        json.dump(existing, f, indent=2)

    print(f"✨🐑 SoftScan found {len(results)} vulnerability(s)! Logged to {SCAN_REPORT}")


# (๑•́ ₃ •̀๑) Lamb Infiltration

def main():
    parser = argparse.ArgumentParser(description="SoftScan Vulnerability Scanner")
    parser.add_argument("--input", type=str, help="Text or code snippet to scan")
    parser.add_argument("--summary", action="store_true", help="Print summary after scan")
    args = parser.parse_args()

    print(ASCII_LAMB)

    if not args.input:
        print("(ノ﹏ヽ) Please provide input text/code with --input")
        return

    findings = scan_text(args.input)
    save_report(findings)

    for f in findings:
        print(f"❗ {f['vulnerability']} | Severity: {f['severity']} | Pattern: {f['pattern']}\n   💡 Recommendation: {f['recommendation']}")

    if args.summary:
        severities = [f['severity'] for f in findings]
        print("\n🧾 Summary Report:")
        for level in set(severities):
            count = severities.count(level)
            print(f"- {level} Severity: {count} finding(s)")

if __name__ == "__main__":
    main()
