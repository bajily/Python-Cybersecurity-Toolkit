# Linux Hardening Auditor

Linux security baseline auditing for SSH settings, sysctl controls and sensitive file permissions using offline configuration evidence.

Review captured Linux configuration text and permission metadata against a documented baseline.

**Python 3.11+ · Standard library · JSON, SARIF 2.1.0 and Markdown reports · MIT license**

## Quick start

```bash
git clone https://github.com/bajily/Python-Cybersecurity-Toolkit.git
cd Python-Cybersecurity-Toolkit/enterprise/linux-hardening-auditor
python security_tool.py --demo --now 2026-10-13T12:00:00Z
python -m unittest discover -v
```

The synthetic example intentionally contains risky conditions. Exit status `1` means a finding met the configured threshold; it is not a crash.

```bash
python security_tool.py example.json --format sarif --output findings.sarif
python security_tool.py example.json --format markdown --output review.md --fail-on critical
python security_tool.py example.json --policy policy.json --suppressions exceptions.json
```

## How the review works

Review captured Linux configuration text and permission metadata against a documented baseline.

Implemented rule families: `LINUX-SENSITIVE-PERMISSIONS`, `LINUX-SHADOW-READ`, `LINUX-SSH-BASELINE`, `LINUX-SSH-CONTEXT`, `LINUX-SYSCTL-BASELINE`.

Each finding includes a rule ID, severity, resource, evidence, a recommended review action and a stable fingerprint. Reports sort findings by severity and resource. No automatic enforcement is performed.

## Input contract

The example below is the minimal supported export structure. Required fields are validated; malformed or ambiguous inputs cause exit status 2.



```json
{
  "sshd_config": "PermitRootLogin yes\nPasswordAuthentication yes\nInclude /etc/ssh/sshd_config.d/*.conf\nMatch User legacy\nPasswordAuthentication yes\n",
  "sysctl": {
    "kernel.randomize_va_space": "0",
    "net.ipv4.conf.all.accept_redirects": "1"
  },
  "files": [
    {
      "path": "/etc/shadow",
      "mode": "0644",
      "owner_uid": 0
    },
    {
      "path": "/etc/ssh/sshd_config",
      "mode": "0666",
      "owner_uid": 1000
    }
  ]
}
```

Identifiers in examples are synthetic. Adapt exports to this exact shape instead of assuming provider APIs use identical field names.

## Policy and integration

Policy defaults and the input fields are documented below and in the audit function. Review thresholds before operational use.

```json
{
  "ssh": {
    "permitrootlogin": "no",
    "passwordauthentication": "no",
    "permitemptypasswords": "no",
    "pubkeyauthentication": "yes"
  },
  "sysctl": {
    "kernel.randomize_va_space": "2",
    "net.ipv4.conf.all.accept_redirects": "0",
    "net.ipv4.conf.all.send_redirects": "0"
  },
  "allow_shadow_group_read": true
}
```

The empty object selects defaults. Every input file is limited to 10 MiB. Duplicate JSON keys and non-finite numbers are rejected. Timestamps require explicit timezones. `--now` makes time-dependent reviews reproducible.

Exit statuses: `0` means no active finding meets `--fail-on`; `1` means the threshold is met; `2` means invalid input or an operational error. Output files are created exclusively and existing evidence is not overwritten. A clean report does not establish that a system is secure.

## Reviewed exceptions

Use a finding's exact fingerprint, an explanation and an expiration date:

```json
[
  {"fingerprint": "COPY-A-FINDING-FINGERPRINT", "reason": "Approved temporary exception; ticket SEC-123", "expires": "2027-01-01T00:00:00Z"}
]
```

Expired exceptions stop suppressing findings. Suppressed findings remain in JSON evidence. Keep exception review separate from code changes.

## Validation and deployment limits

Unit tests exercise the detector, clean inputs, boundary conditions, report generation, input failures and exception expiry. GitHub Actions runs the suite on Python 3.11 and 3.14.

SSHD global directives use first-value semantics. Includes and Match sections are surfaced for review rather than guessed. The checks are a focused baseline, not a CIS certification or an assessment of every distribution setting.

Version 0.1.0 is an initial implementation for controlled evaluation. Establish a company-specific baseline, test representative sanitized exports, review false positives and perform an independent security review before relying on it operationally. These projects have no measured production performance or effectiveness claims.

## Security and contributions

Keep secrets, private inventories, real email, signing keys and sensitive logs out of public issues and repositories. Publish only synthetic or sanitized fixtures. Findings and generated reports can contain private asset identifiers; protect them as internal security records.

For a suspected vulnerability, use GitHub private reporting if available. Otherwise describe the issue without secrets or sensitive exploit details. Include a reproducible synthetic test with focused changes, and run the test suite before proposing a contribution.

## بالعربية

أداة دفاعية لتحليل الأدلة الأمنية وإنتاج نتائج قابلة للمراجعة مع قواعد واضحة واختبارات. تعمل على مدخلات موثقة وتدعم ضبط السياسات والاستثناءات المؤقتة. يلزم تقييمها على بيئة الشركة قبل الاعتماد التشغيلي؛ لا تقدّم ضمانًا شاملًا لحماية الأنظمة.
