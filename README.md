# Python Cybersecurity Toolkit · Defensive Security Automation

A collection of **10 independently runnable defensive security projects** for reviewing Linux and Windows baselines, Docker and Kubernetes configurations, API access logs, audit integrity, configuration drift, phishing evidence, threat intelligence and incident response workflows.

Built for controlled enterprise security evaluation with documented JSON inputs, configurable policy checks, synthetic fixtures, tests, redacted evidence where applicable, and JSON/SARIF/Markdown reports. Python 3.11+; standard library only.

[Defensive security projects](#security-projects-in-this-repository) · [Python quickstart](#run-a-python-security-audit) · [Cloud and IAM tools](#complementary-standalone-security-projects) · [Evaluation limits](#evaluation-scope) · [العربية](#بالعربية)

## Security projects in this repository

| Project | Purpose |
|---|---|
| [Linux Hardening Auditor](https://github.com/bajily/Python-Cybersecurity-Toolkit/tree/main/enterprise/linux-hardening-auditor) | Review captured Linux configuration text and permission metadata against a documented baseline. |
| [Windows Security Baseline Auditor](https://github.com/bajily/Python-Cybersecurity-Toolkit/tree/main/enterprise/windows-security-baseline-auditor) | Evaluate a normalized endpoint control export and report missing, disabled or unknown protections. |
| [Container Security Auditor](https://github.com/bajily/Python-Cybersecurity-Toolkit/tree/main/enterprise/container-security-auditor) | Review Dockerfile text before merging an application container build. |
| [Kubernetes Manifest Guard](https://github.com/bajily/Python-Cybersecurity-Toolkit/tree/main/enterprise/kubernetes-manifest-guard) | Review exported Kubernetes JSON resources and explain effective pod/container security-context gaps. |
| [API Access Log Detector](https://github.com/bajily/Python-Cybersecurity-Toolkit/tree/main/enterprise/api-access-log-detector) | Triage normalized request logs into explainable client and route activity findings. |
| [Audit Log Integrity Ledger](https://github.com/bajily/Python-Cybersecurity-Toolkit/tree/main/enterprise/audit-log-integrity-ledger) | Verify a log export against a protected signing key and an independently stored final-head anchor. |
| [Security Configuration Drift](https://github.com/bajily/Python-Cybersecurity-Toolkit/tree/main/enterprise/security-config-drift) | Compare two reviewed configuration snapshots and prioritize changed security-relevant paths. |
| [Phishing Email Triage](https://github.com/bajily/Python-Cybersecurity-Toolkit/tree/main/enterprise/phishing-email-triage) | Analyze bounded MIME email content without opening attachments or following links. |
| [Threat Intelligence Matcher](https://github.com/bajily/Python-Cybersecurity-Toolkit/tree/main/enterprise/threat-intelligence-matcher) | Match normalized observations against a maintained local indicator dataset. |
| [Incident Response Orchestrator](https://github.com/bajily/Python-Cybersecurity-Toolkit/tree/main/enterprise/incident-response-orchestrator) | Validate a declarative incident playbook and generate an auditable local response plan. |

<a name="run-a-project"></a>

## Run a Python security audit

```bash
git clone https://github.com/bajily/Python-Cybersecurity-Toolkit.git
cd Python-Cybersecurity-Toolkit/enterprise/kubernetes-manifest-guard
python security_tool.py --demo --now 2026-10-13T12:00:00Z
python -m unittest discover -v
```

Each project directory contains its own engine, test suite, synthetic input, README and MIT license. Exit 1 means a finding met the configured threshold. See that project's README for its input contract and evaluation limits.

GitHub Actions uses a project/Python matrix to test these ten directories independently on Python 3.11 and 3.14. Earlier learning scripts at repository root are outside this enterprise test matrix.

## Complementary standalone security projects

| Project | Purpose |
|---|---|
| [Identity Access Review](https://github.com/bajily/identity-access-review) | Review normalized identity and group exports; explain inherited business and administrative permissions. |
| [Cloud IAM Policy Auditor](https://github.com/bajily/cloud-iam-policy-auditor) | Statically inspect exported IAM JSON before a reviewer approves access changes. |
| [Cloud Storage Exposure Audit](https://github.com/bajily/cloud-storage-exposure-audit) | Review a normalized storage inventory and prioritize exposure using data classification. |
| [Network Segmentation Auditor](https://github.com/bajily/network-segmentation-auditor) | Test a proposed ordered firewall policy against explicit expected traffic decisions. |
| [TLS Certificate Auditor](https://github.com/bajily/tls-certificate-auditor) | Review exported certificate inventory or connect to explicitly listed authorized TLS endpoints. |
| [Software Supply Chain Auditor](https://github.com/bajily/software-supply-chain-auditor) | Trace vulnerable dependencies from an application through a CycloneDX dependency graph. |
| [Secrets Exposure Scanner](https://github.com/bajily/secrets-exposure-scanner) | Detect likely credential material in a repository without printing matched secret values. |
| [Vulnerability Prioritizer](https://github.com/bajily/vulnerability-prioritizer) | Produce a reproducible patch queue from normalized vulnerability and asset exports. |
| [Ransomware Canary Detector](https://github.com/bajily/ransomware-canary-detector) | Correlate exported filesystem events and canary touches into host-level triage findings. |
| [Backup Restore Verifier](https://github.com/bajily/backup-restore-verifier) | Verify an exported backup manifest against a local snapshot before a recovery exercise. |

## Authorized penetration-testing tools

For scoped live web, API, TCP, TLS, SSH, DNS, OpenID Connect and JWT assessment tasks, see the [Enterprise Pentest Suite — 10 Python assessment programs](https://github.com/bajily/enterprise-pentest-suite). Browse the [complete cybersecurity project directory](https://github.com/bajily#enterprise-security-project-directory) for related tools.

Optional [sponsorship of Anas Elgaili's open-source work](https://github.com/sponsors/bajily) helps improve documentation, examples, tests and bug fixes.

## Evaluation scope

These initial implementations support security review and triage. Validate exports, policies and false positives in your own environment before relying on them operationally. They do not provide universal protection, full provider-policy simulation or compliance certification.

## بالعربية

مجموعة تضم عشرة مشاريع دفاعية مستقلة داخل هذا المستودع، وروابط لعشرة مشاريع مكمّلة في مستودعات منفصلة. تغطي فحص الأنظمة والحاويات والسجلات والإعدادات والتصيّد ومؤشرات التهديد والتخطيط للاستجابة، مع توثيق واختبارات وأمثلة تشغيل.

## Earlier learning scripts

The following root-level scripts are older educational experiments; their documented limitations remain relevant.

## Python Cybersecurity Toolkit

A collection of small Python learning scripts covering DNS lookups, network discovery, hashing, and web-security lab exercises.

This repository contains early experiments. The scripts have different dependencies and maturity levels; the table below distinguishes them so users can choose an appropriate starting point.

### Script index

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

### Start with DNS resolution

```bash
git clone https://github.com/bajily/Python-Cybersecurity-Toolkit.git
cd Python-Cybersecurity-Toolkit
python Socket_Python_enumeration.py
```

Enter a domain you own or have permission to investigate. The script checks `www`, `mail`, `api`, `vpn`, `dev`, and `admin` and prints resolved IPv4 addresses.

For scripts with external dependencies, create a virtual environment and install only the packages required by the selected script. Network access and operating-system permissions vary by tool.

### Scope and responsible use

Use active network and web tests only in systems you own or an explicitly authorized lab. Keep keyboard experiments local and consensual. Do not commit credentials, captured input, real logs, or private target data.

The scripts are educational examples, not production security tools. A reflected payload or error message alone does not prove a vulnerability. Offline defensive projects are available in [SOC Portfolio](https://github.com/bajily/SOC-Portfolio-).

### Development direction

- Standardize CLI arguments and input validation.
- Add timeouts and structured results to network tools.
- Add isolated tests before changing active lab scripts.
- Prioritize reproducible defensive workflows and clear limitations.

### بالعربية

مجموعة تجارب تعليمية في Python للشبكات والأمن السيبراني. يوضح الجدول وظيفة كل ملف ومتطلباته وحالته، مع بداية بسيطة باستخدام DNS وحدود واضحة للاستخدام في المختبرات المصرّح بها.
