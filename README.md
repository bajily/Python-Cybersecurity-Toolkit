# Python Cybersecurity Toolkit

A collection of small Python learning scripts covering DNS lookups, network discovery, hashing, and web-security lab exercises.

This repository contains early experiments. The scripts have different dependencies and maturity levels; the table below distinguishes them so users can choose an appropriate starting point.

## Script index

| Script | Purpose | Dependencies / status |
|---|---|---|
| `Socket_Python_enumeration.py` | Resolve a small predefined set of subdomains | Python standard library |
| `DNSPython_For_Web_Enumeration.py` | Query DNS A records | `dnspython` |
| `After_find_Subdomain_Requests_Python_Enumeration.py` | Print an HTTP response status | `requests`; 5-second timeout |
| `Network_scanner_ARP.py` | Discover hosts using ARP in a local lab | `scapy`; hardcoded `wlan0` interface |
| `Port_scanner.py` | Sequential TCP port checks | `pyfiglet`; may take a long time |
| `Hash_cracker_MD5.py` | Compare a local wordlist with an MD5 hash | `pyfiglet`; lab exercise |
| `Hash_cracker_SHA256.py` | Compare a local wordlist with a SHA-256 hash | `pyfiglet`; banner currently says MD5 |
| `Vulnerability_scanner.py` | Basic SQLi/XSS indicators in a web lab | `requests`; heuristic, no request timeout |
| `Keylogger.py` | Record and replay local keyboard input | `keyboard`; sensitive lab experiment |
| `RCE_Exploit.py` | Historical remote-command lab experiment | Incomplete; contains indentation errors and is not runnable |

## Start with DNS resolution

```bash
git clone https://github.com/bajily/Python-Cybersecurity-Toolkit.git
cd Python-Cybersecurity-Toolkit
python Socket_Python_enumeration.py
```

Enter a domain you own or have permission to investigate. The script checks `www`, `mail`, `api`, `vpn`, `dev`, and `admin` and prints resolved IPv4 addresses.

For scripts with external dependencies, create a virtual environment and install only the packages required by the selected script. Network access and operating-system permissions vary by tool.

## Scope and responsible use

Use active network and web tests only in systems you own or an explicitly authorized lab. Keep keyboard experiments local and consensual. Do not commit credentials, captured input, real logs, or private target data.

The scripts are educational examples, not production security tools. A reflected payload or error message alone does not prove a vulnerability. Offline defensive projects are available in [SOC Portfolio](https://github.com/bajily/SOC-Portfolio-).

## Development direction

- Standardize CLI arguments and input validation.
- Add timeouts and structured results to network tools.
- Add isolated tests before changing active lab scripts.
- Prioritize reproducible defensive workflows and clear limitations.

## بالعربية

مجموعة تجارب تعليمية في Python للشبكات والأمن السيبراني. يوضح الجدول وظيفة كل ملف ومتطلباته وحالته، مع بداية بسيطة باستخدام DNS وحدود واضحة للاستخدام في المختبرات المصرّح بها.
