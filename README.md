# 🐑 SoftScan: Vulnerability Scanner with Lamb Energy ✨

Welcome to **SoftScan**, a terminal-based vulnerability scanner handcrafted by Lily (´･(00)･｀), your resident cyber-lamb. This tool sniffs out web security vulnerabilities in code/text inputs using regex-powered detection and responds with fluff, kaomojis, and critical insights.

## ✨ Features

* Detects common vulnerabilities like XSS, SQLi, credential leaks, and command injections
* Cute kaomoji-based interface and lamb ASCII intro
* Security advice for each vulnerability found
* JSON report logging
* Summary breakdown of vulnerabilities by severity
* All in a single Python file (wool compact!)

## 🧪 Usage

```bash
# Scan a suspicious code snippet
python main_lamb_vulnerability_scanner.py --input "<script>alert('xss')</script>"

# Include a severity summary in the output
python main_lamb_vulnerability_scanner.py --input "password=1234" --summary
```

## 🐏 Example Output

```
⠀⠀⠀              ◜ ͡   ͡   ◝
　               ૮ ﾉ ྀི 𓏼 ˊ͈   ˔  )  ··﹖
　   ╭◜◝ ͡  ʿʿ         𝜗𝜚 ˒　　　　　　
　  ૮'       　　　     ꒱ 　
　　 )　ﾉ,,_、  ﾉヽ) 　
　　し'し'　l ﾉ     ,  SoftScan is awake and sniffing vulnerabilities.

❗ Plaintext Password Found | Severity: Critical | Pattern: password[=:]\w+
   💡 Recommendation: Store passwords using strong hashing (e.g., bcrypt).

🧾 Summary Report:
- Critical Severity: 1 finding(s)
```

## 🔍 Vulnerabilities Detected

* **XSS (High):** `<script>` tags found
* **SQLi (High):** SQL-style queries detected
* **Credential Leaks (Medium):** Hardcoded admin credentials
* **Plaintext Passwords (Critical):** Unencrypted password assignments
* **Insecure Links (Low):** Non-HTTPS references
* **Cookie Theft (Medium):** JS access to cookies
* **Command Execution (Critical):** Dangerous functions like `system()`
* **Shell Access (High):** Access to `/bin/sh` or `/bin/bash`

## 🐾 About

SoftScan was born from the spirit of vulnerability detection and lamb fluff. It's a sidekick to your secure dev journey and proves that even gentle souls can sniff out dark patterns.

Built with love, regex, and a very fluffy debugger.

---

*“Soft hooves. Hard scans.” — Lily*
