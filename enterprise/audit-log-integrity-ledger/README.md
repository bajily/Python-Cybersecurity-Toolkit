# Audit Log Integrity Ledger

Tamper-evident audit log verification with canonical JSON, sequence checks, SHA-256 chaining, HMAC authentication and trusted-head anchors.

Verify a log export against a protected signing key and an independently stored final-head anchor.

**Python 3.11+ · Standard library · JSON, SARIF 2.1.0 and Markdown reports · MIT license**

## Quick start

```bash
git clone https://github.com/bajily/Python-Cybersecurity-Toolkit.git
cd Python-Cybersecurity-Toolkit/enterprise/audit-log-integrity-ledger
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

Verify a log export against a protected signing key and an independently stored final-head anchor.

Implemented rule families: `LEDGER-DEMONSTRATION-KEY`, `LEDGER-HEAD-MISMATCH`, `LEDGER-RECORD-INTEGRITY`, `LEDGER-TRUSTED-ANCHOR`.

Each finding includes a rule ID, severity, resource, evidence, a recommended review action and a stable fingerprint. Reports sort findings by severity and resource. No automatic enforcement is performed.

## Input contract

The example below is the minimal supported export structure. Required fields are validated; malformed or ambiguous inputs cause exit status 2.

For real verification set key_env to the exact name of a protected environment variable containing at least 32 key bytes. Keep the key and expected_head independently protected. The special __DEMONSTRATION_ONLY__ key is public, always identified in findings, and provides no production trust.

```json
{
  "key_env": "__DEMONSTRATION_ONLY__",
  "initial_head": "0000000000000000000000000000000000000000000000000000000000000000",
  "expected_head": "a30677032dfdbd3d3375738c206067c3e0808cf187db5ad8591565c6a2ed7632",
  "records": [
    {
      "sequence": 1,
      "previous_hash": "0000000000000000000000000000000000000000000000000000000000000000",
      "timestamp": "2026-10-13T11:00:00Z",
      "event": {
        "action": "synthetic-login",
        "outcome": "altered"
      },
      "hash": "a30677032dfdbd3d3375738c206067c3e0808cf187db5ad8591565c6a2ed7632",
      "hmac": "728e90059b77de387b26730439d4d3bbd7e68f797fea497f01a1c72904fe8c7d"
    }
  ]
}
```

Identifiers in examples are synthetic. Adapt exports to this exact shape instead of assuming provider APIs use identical field names.

## Policy and integration

Policy defaults and the input fields are documented below and in the audit function. Review thresholds before operational use.

```json
{
  "starting_sequence": 1
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

Keys and trusted anchors must be stored separately from the log. A hash chain alone cannot detect a rewritten or truncated history without a trusted anchor. This project does not provide immutable storage or trusted timestamps.

Version 0.1.0 is an initial implementation for controlled evaluation. Establish a company-specific baseline, test representative sanitized exports, review false positives and perform an independent security review before relying on it operationally. These projects have no measured production performance or effectiveness claims.

## Security and contributions

Keep secrets, private inventories, real email, signing keys and sensitive logs out of public issues and repositories. Publish only synthetic or sanitized fixtures. Findings and generated reports can contain private asset identifiers; protect them as internal security records.

For a suspected vulnerability, use GitHub private reporting if available. Otherwise describe the issue without secrets or sensitive exploit details. Include a reproducible synthetic test with focused changes, and run the test suite before proposing a contribution.

## بالعربية

أداة دفاعية لتحليل الأدلة الأمنية وإنتاج نتائج قابلة للمراجعة مع قواعد واضحة واختبارات. تعمل على مدخلات موثقة وتدعم ضبط السياسات والاستثناءات المؤقتة. يلزم تقييمها على بيئة الشركة قبل الاعتماد التشغيلي؛ لا تقدّم ضمانًا شاملًا لحماية الأنظمة.
