# Phishing Email Triage

Offline phishing email analysis for suspicious URLs, sender-domain inconsistencies, risky attachments and trusted authentication-result evidence.

Analyze bounded MIME email content without opening attachments or following links.

**Python 3.11+ · Standard library · JSON, SARIF 2.1.0 and Markdown reports · MIT license**

## Quick start

```bash
git clone https://github.com/bajily/Python-Cybersecurity-Toolkit.git
cd Python-Cybersecurity-Toolkit/enterprise/phishing-email-triage
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

Analyze bounded MIME email content without opening attachments or following links.

Implemented rule families: `MAIL-AUTH-FAILURE`, `MAIL-AUTH-UNTRUSTED`, `MAIL-DECODE-GAP`, `MAIL-MALFORMED-URL`, `MAIL-REPLY-DOMAIN`, `MAIL-RISKY-ATTACHMENT`, `MAIL-SUSPICIOUS-URL`.

Each finding includes a rule ID, severity, resource, evidence, a recommended review action and a stable fingerprint. Reports sort findings by severity and resource. No automatic enforcement is performed.

## Input contract

The example below is the minimal supported export structure. Required fields are validated; malformed or ambiguous inputs cause exit status 2.

A message can provide an explicitly selected local path to an .eml file instead of inline eml text. trusted_authentication_boundary must only be true for a receiver export whose ingress strips forged Authentication-Results headers; an authserv-id string alone is not a trust boundary.

```json
{
  "messages": [
    {
      "id": "synthetic-email",
      "trusted_authentication_boundary": false,
      "eml": "From: Example Support <support@example.com>\nReply-To: help@different.example\nTo: analyst@example.org\nSubject: Synthetic training message\nAuthentication-Results: forged.example; dmarc=fail\nContent-Type: text/plain; charset=utf-8\n\nReview https://portal.example@192.0.2.20/login\n"
    }
  ]
}
```

Identifiers in examples are synthetic. Adapt exports to this exact shape instead of assuming provider APIs use identical field names.

## Policy and integration

Policy defaults and the input fields are documented below and in the audit function. Review thresholds before operational use.

```json
{
  "trusted_authserv_ids": [],
  "risky_attachment_extensions": [
    ".exe",
    ".scr",
    ".js",
    ".vbs",
    ".ps1",
    ".docm",
    ".xlsm",
    ".lnk",
    ".iso"
  ]
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

Authentication-Results is trusted only when its authserv-id is explicitly configured. Indicators are heuristics; legitimate mail may trigger them. The tool never sends email, fetches URLs or detonates attachments.

Version 0.1.0 is an initial implementation for controlled evaluation. Establish a company-specific baseline, test representative sanitized exports, review false positives and perform an independent security review before relying on it operationally. These projects have no measured production performance or effectiveness claims.

## Security and contributions

Keep secrets, private inventories, real email, signing keys and sensitive logs out of public issues and repositories. Publish only synthetic or sanitized fixtures. Findings and generated reports can contain private asset identifiers; protect them as internal security records.

For a suspected vulnerability, use GitHub private reporting if available. Otherwise describe the issue without secrets or sensitive exploit details. Include a reproducible synthetic test with focused changes, and run the test suite before proposing a contribution.

## بالعربية

أداة دفاعية لتحليل الأدلة الأمنية وإنتاج نتائج قابلة للمراجعة مع قواعد واضحة واختبارات. تعمل على مدخلات موثقة وتدعم ضبط السياسات والاستثناءات المؤقتة. يلزم تقييمها على بيئة الشركة قبل الاعتماد التشغيلي؛ لا تقدّم ضمانًا شاملًا لحماية الأنظمة.
