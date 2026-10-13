# API Access Log Detector

API security log analytics for authentication-failure bursts, route enumeration and unusual outbound response volume with rolling-window evidence.

Triage normalized request logs into explainable client and route activity findings.

**Python 3.11+ · Standard library · JSON, SARIF 2.1.0 and Markdown reports · MIT license**

## Quick start

```bash
git clone https://github.com/bajily/Python-Cybersecurity-Toolkit.git
cd Python-Cybersecurity-Toolkit/enterprise/api-access-log-detector
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

Triage normalized request logs into explainable client and route activity findings.

Implemented rule families: `API-AUTH-FAILURES`, `API-RESPONSE-VOLUME`, `API-ROUTE-ENUMERATION`.

Each finding includes a rule ID, severity, resource, evidence, a recommended review action and a stable fingerprint. Reports sort findings by severity and resource. No automatic enforcement is performed.

## Input contract

The example below is the minimal supported export structure. Required fields are validated; malformed or ambiguous inputs cause exit status 2.



```json
{
  "events": [
    {
      "id": "synthetic-request-0",
      "timestamp": "2026-10-13T11:00:00Z",
      "client": "192.0.2.20",
      "status": 401,
      "path": "/private/route-0",
      "response_bytes": 100
    },
    {
      "id": "synthetic-request-1",
      "timestamp": "2026-10-13T11:00:01Z",
      "client": "192.0.2.20",
      "status": 401,
      "path": "/private/route-1",
      "response_bytes": 100
    },
    {
      "id": "synthetic-request-2",
      "timestamp": "2026-10-13T11:00:02Z",
      "client": "192.0.2.20",
      "status": 401,
      "path": "/private/route-2",
      "response_bytes": 100
    },
    {
      "id": "synthetic-request-3",
      "timestamp": "2026-10-13T11:00:03Z",
      "client": "192.0.2.20",
      "status": 401,
      "path": "/private/route-3",
      "response_bytes": 100
    },
    {
      "id": "synthetic-request-4",
      "timestamp": "2026-10-13T11:00:04Z",
      "client": "192.0.2.20",
      "status": 401,
      "path": "/private/route-4",
      "response_bytes": 100
    },
    {
      "id": "synthetic-request-5",
      "timestamp": "2026-10-13T11:00:05Z",
      "client": "192.0.2.20",
      "status": 401,
      "path": "/private/route-5",
      "response_bytes": 100
    },
    {
      "id": "synthetic-request-6",
      "timestamp": "2026-10-13T11:00:06Z",
      "client": "192.0.2.20",
      "status": 401,
      "path": "/private/route-6",
      "response_bytes": 100
    },
    {
      "id": "synthetic-request-7",
      "timestamp": "2026-10-13T11:00:07Z",
      "client": "192.0.2.20",
      "status": 401,
      "path": "/private/route-7",
      "response_bytes": 100
    },
    {
      "id": "synthetic-request-8",
      "timestamp": "2026-10-13T11:00:08Z",
      "client": "192.0.2.20",
      "status": 401,
      "path": "/private/route-8",
      "response_bytes": 100
    },
    {
      "id": "synthetic-request-9",
      "timestamp": "2026-10-13T11:00:09Z",
      "client": "192.0.2.20",
      "status": 401,
      "path": "/private/route-9",
      "response_bytes": 100
    },
    {
      "id": "synthetic-request-10",
      "timestamp": "2026-10-13T11:00:10Z",
      "client": "192.0.2.20",
      "status": 401,
      "path": "/private/route-10",
      "response_bytes": 100
    },
    {
      "id": "synthetic-request-11",
      "timestamp": "2026-10-13T11:00:11Z",
      "client": "192.0.2.20",
      "status": 401,
      "path": "/private/route-11",
      "response_bytes": 100
    },
    {
      "id": "synthetic-request-12",
      "timestamp": "2026-10-13T11:00:12Z",
      "client": "192.0.2.20",
      "status": 401,
      "path": "/private/route-12",
      "response_bytes": 100
    },
    {
      "id": "synthetic-request-13",
      "timestamp": "2026-10-13T11:00:13Z",
      "client": "192.0.2.20",
      "status": 401,
      "path": "/private/route-13",
      "response_bytes": 100
    },
    {
      "id": "synthetic-request-14",
      "timestamp": "2026-10-13T11:00:14Z",
      "client": "192.0.2.20",
      "status": 401,
      "path": "/private/route-14",
      "response_bytes": 100
    },
    {
      "id": "synthetic-request-15",
      "timestamp": "2026-10-13T11:00:15Z",
      "client": "192.0.2.20",
      "status": 401,
      "path": "/private/route-15",
      "response_bytes": 100
    },
    {
      "id": "synthetic-request-16",
      "timestamp": "2026-10-13T11:00:16Z",
      "client": "192.0.2.20",
      "status": 401,
      "path": "/private/route-16",
      "response_bytes": 100
    },
    {
      "id": "synthetic-request-17",
      "timestamp": "2026-10-13T11:00:17Z",
      "client": "192.0.2.20",
      "status": 401,
      "path": "/private/route-17",
      "response_bytes": 100
    },
    {
      "id": "synthetic-request-18",
      "timestamp": "2026-10-13T11:00:18Z",
      "client": "192.0.2.20",
      "status": 401,
      "path": "/private/route-18",
      "response_bytes": 100
    },
    {
      "id": "synthetic-request-19",
      "timestamp": "2026-10-13T11:00:19Z",
      "client": "192.0.2.20",
      "status": 401,
      "path": "/private/route-19",
      "response_bytes": 100
    },
    {
      "id": "synthetic-request-20",
      "timestamp": "2026-10-13T11:00:20Z",
      "client": "192.0.2.20",
      "status": 401,
      "path": "/private/route-20",
      "response_bytes": 100
    },
    {
      "id": "synthetic-request-21",
      "timestamp": "2026-10-13T11:00:21Z",
      "client": "192.0.2.20",
      "status": 401,
      "path": "/private/route-21",
      "response_bytes": 100
    },
    {
      "id": "synthetic-request-22",
      "timestamp": "2026-10-13T11:00:22Z",
      "client": "192.0.2.20",
      "status": 401,
      "path": "/private/route-22",
      "response_bytes": 100
    },
    {
      "id": "synthetic-request-23",
      "timestamp": "2026-10-13T11:00:23Z",
      "client": "192.0.2.20",
      "status": 401,
      "path": "/private/route-23",
      "response_bytes": 100
    },
    {
      "id": "synthetic-request-24",
      "timestamp": "2026-10-13T11:00:24Z",
      "client": "192.0.2.20",
      "status": 401,
      "path": "/private/route-24",
      "response_bytes": 100
    }
  ]
}
```

Identifiers in examples are synthetic. Adapt exports to this exact shape instead of assuming provider APIs use identical field names.

## Policy and integration

Policy defaults and the input fields are documented below and in the audit function. Review thresholds before operational use.

```json
{
  "window_seconds": 300,
  "authentication_failure_threshold": 5,
  "unique_route_threshold": 20,
  "excluded_clients": []
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

Batch analysis holds events in memory. Client identifiers must be normalized upstream, especially behind proxies. Large responses and many routes can be legitimate; findings are triage signals, not proof of exploitation.

Version 0.1.0 is an initial implementation for controlled evaluation. Establish a company-specific baseline, test representative sanitized exports, review false positives and perform an independent security review before relying on it operationally. These projects have no measured production performance or effectiveness claims.

## Security and contributions

Keep secrets, private inventories, real email, signing keys and sensitive logs out of public issues and repositories. Publish only synthetic or sanitized fixtures. Findings and generated reports can contain private asset identifiers; protect them as internal security records.

For a suspected vulnerability, use GitHub private reporting if available. Otherwise describe the issue without secrets or sensitive exploit details. Include a reproducible synthetic test with focused changes, and run the test suite before proposing a contribution.

## بالعربية

أداة دفاعية لتحليل الأدلة الأمنية وإنتاج نتائج قابلة للمراجعة مع قواعد واضحة واختبارات. تعمل على مدخلات موثقة وتدعم ضبط السياسات والاستثناءات المؤقتة. يلزم تقييمها على بيئة الشركة قبل الاعتماد التشغيلي؛ لا تقدّم ضمانًا شاملًا لحماية الأنظمة.
