"""Shared validation, findings, suppressions and reporting for defensive tools."""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import math
import sys
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

VERSION = "0.1.0"
SEVERITIES = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("timestamp must be an ISO 8601 string with a timezone")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("timestamps require a timezone")
    return result.astimezone(timezone.utc)


def object_value(value, label="input"):
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def records(data, key, required=()):
    object_value(data)
    rows = data.get(key)
    if not isinstance(rows, list):
        raise ValueError(f"{key} must be an array")
    for index, row in enumerate(rows):
        object_value(row, f"{key}[{index}]")
        if any(field not in row for field in required):
            raise ValueError(f"{key}[{index}] is missing required fields: {', '.join(required)}")
    return rows


def text(value, label):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    return value


def boolean(value, label):
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be boolean")
    return value


def number(value, label, minimum=0, maximum=None):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(f"{label} must be a finite number")
    if value < minimum or (maximum is not None and value > maximum):
        raise ValueError(f"{label} is outside the permitted range")
    return value


def string_list(value, label):
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{label} must be an array of non-empty strings")
    return value


def setting(policy, key, default, minimum=0, maximum=None):
    return number(policy.get(key, default), f"policy.{key}", minimum, maximum)


def finding(rule, severity, resource, title, evidence, remediation, **extra):
    if severity not in SEVERITIES:
        raise ValueError("unknown finding severity")
    resource = str(resource)
    stable = json.dumps([TOOL, rule, resource, extra.get("subject", "")], ensure_ascii=False)
    result = {"rule": rule, "severity": severity, "resource": resource,
              "title": title, "evidence": evidence, "remediation": remediation,
              "fingerprint": hashlib.sha256(stable.encode()).hexdigest()[:24]}
    result.update(extra)
    return result


def unique_rows(rows, key):
    result = {}
    for row in rows:
        identifier = text(row[key], key)
        if identifier in result:
            raise ValueError(f"duplicate {key} in inventory")
        result[identifier] = row
    return result


def decode_json(content):
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("JSON contains a duplicate key")
            result[key] = value
        return result
    return json.loads(content, object_pairs_hook=reject_duplicates,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("non-finite JSON number")))


def load_json(path):
    if path.stat().st_size > 10 * 1024 * 1024:
        raise ValueError("JSON input exceeds the 10 MiB limit")
    return decode_json(path.read_text(encoding="utf-8-sig"))


def build_report(findings, suppressions=(), now=None):
    now = now or datetime.now(timezone.utc)
    active, suppressed = [], []
    fingerprints = set()
    for suppression in suppressions:
        object_value(suppression, "suppression")
        text(suppression.get("fingerprint"), "suppression fingerprint")
        text(suppression.get("reason"), "suppression reason")
        timestamp(suppression.get("expires"))
        if suppression["fingerprint"] in fingerprints:
            raise ValueError("duplicate suppression fingerprint")
        fingerprints.add(suppression["fingerprint"])
    known = {item["fingerprint"]: item for item in suppressions
             if timestamp(item["expires"]) > now}
    for item in findings:
        if item["fingerprint"] in known:
            suppressed.append({**item, "suppression_reason": known[item["fingerprint"]]["reason"]})
        else:
            active.append(item)
    active.sort(key=lambda item: (-SEVERITIES[item["severity"]], item["resource"], item["rule"], item["fingerprint"]))
    return {"tool": TOOL, "version": VERSION, "generated_at": now.isoformat(),
            "summary": dict(Counter(item["severity"] for item in active)),
            "findings": active, "suppressed": suppressed}


def sarif(report):
    rules = {item["rule"]: item["title"] for item in report["findings"]}
    results = []
    for item in report["findings"]:
        results.append({"ruleId": item["rule"],
                        "level": "error" if SEVERITIES[item["severity"]] >= 3 else "warning" if SEVERITIES[item["severity"]] >= 1 else "note",
                        "message": {"text": item["title"] + ". " + item["remediation"]},
                        "locations": [{"logicalLocations": [{"name": item["resource"]}]}],
                        "partialFingerprints": {"securityToolFingerprint/v1": item["fingerprint"]},
                        "properties": {"severity": item["severity"], "evidence": item["evidence"]}})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": TOOL, "version": VERSION,
                       "rules": [{"id": key, "shortDescription": {"text": title}} for key, title in sorted(rules.items())]}},
                       "results": results}]}


def markdown(report):
    def escape(value):
        return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")
    lines = [f"# {TOOL} report", "", f"Version: {VERSION}. Findings: {len(report['findings'])}.", "",
             "| Severity | Resource | Finding | Recommended action |", "|---|---|---|---|"]
    for item in report["findings"]:
        lines.append("| " + " | ".join(escape(item[key]) for key in ("severity", "resource", "title", "remediation")) + " |")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument("input", nargs="?", type=Path, help="JSON inventory, event export or tool configuration")
    parser.add_argument("--demo", action="store_true", help="run the embedded synthetic example")
    parser.add_argument("--policy", type=Path, help="JSON object overriding documented defaults")
    parser.add_argument("--suppressions", type=Path, help="JSON array: fingerprint, reason, expires")
    parser.add_argument("--format", choices=["json", "sarif", "markdown"], default="json")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--fail-on", choices=list(SEVERITIES), default="high")
    parser.add_argument("--now", help="timezone-aware ISO timestamp for reproducible reviews")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args()
    if args.demo == bool(args.input):
        parser.error("provide exactly one of input or --demo")
    try:
        now = timestamp(args.now) if args.now else datetime.now(timezone.utc)
        data = object_value(json.loads(json.dumps(DEMO)) if args.demo else load_json(args.input))
        policy = object_value(load_json(args.policy), "policy") if args.policy else {}
        suppressions = load_json(args.suppressions) if args.suppressions else []
        if not isinstance(suppressions, list):
            raise ValueError("suppressions must be an array")
        report = build_report(audit(data, policy, now), suppressions, now)
        content = markdown(report) if args.format == "markdown" else json.dumps(sarif(report) if args.format == "sarif" else report, indent=2, ensure_ascii=False) + "\n"
        if args.output:
            # Exclusive creation keeps earlier evidence from being overwritten.
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(content)
        else:
            print(content, end="")
        return int(any(SEVERITIES[item["severity"]] >= SEVERITIES[args.fail_on] for item in report["findings"]))
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        parser.exit(2, f"error: {type(exc).__name__}: {exc}\n")
import hmac
import os
import re

TOOL = "audit-log-integrity-ledger"
DESCRIPTION = "Verify sequence, hash-chain, HMAC tags and independently trusted audit-log head anchors."
DEMO_KEY = b"public-demonstration-key-not-for-real-logs-2026"


def canonical_event(record):
    material = {key: record[key] for key in ("sequence", "previous_hash", "timestamp", "event")}
    return json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def sign_record(record, key):
    digest = hashlib.sha256(canonical_event(record)).hexdigest()
    return {**record, "hash": digest, "hmac": hmac.new(key, digest.encode(), hashlib.sha256).hexdigest()}


_demo_record = sign_record({"sequence": 1, "previous_hash": "0" * 64, "timestamp": "2026-10-13T11:00:00Z", "event": {"action": "synthetic-login", "outcome": "success"}}, DEMO_KEY)
DEMO = {"key_env": "__DEMONSTRATION_ONLY__", "initial_head": "0" * 64, "expected_head": _demo_record["hash"],
        "records": [{**_demo_record, "event": {"action": "synthetic-login", "outcome": "altered"}}]}


def audit(data, policy, now):
    object_value(data)
    rows = records(data, "records", ("sequence", "previous_hash", "timestamp", "event", "hash", "hmac"))
    environment_name = text(data.get("key_env"), "key_env")
    result = []
    if environment_name == "__DEMONSTRATION_ONLY__":
        key = DEMO_KEY
        result.append(finding("LEDGER-DEMONSTRATION-KEY", "info", "ledger", "Public synthetic signing key is in use",
                              {"synthetic_key": True}, "Use a protected independent signing key for any real log verification."))
    else:
        if re.fullmatch(r"[A-Z][A-Z0-9_]{1,63}", environment_name) is None:
            raise ValueError("key_env must name a specific uppercase environment variable")
        value = os.environ.get(environment_name)
        if value is None or len(value.encode()) < 32:
            raise ValueError("the configured signing-key variable must contain at least 32 bytes")
        key = value.encode()
    initial = data.get("initial_head", "0" * 64)
    expected_head = data.get("expected_head")
    if not isinstance(initial, str) or re.fullmatch(r"[0-9a-f]{64}", initial) is None:
        raise ValueError("initial_head must be a lowercase SHA-256 digest")
    if expected_head is None:
        result.append(finding("LEDGER-TRUSTED-ANCHOR", "high", "ledger", "Independent final-head anchor is missing",
                              {"expected_head_present": False}, "Supply a final-head anchor obtained from an independently protected record."))
    elif not isinstance(expected_head, str) or re.fullmatch(r"[0-9a-f]{64}", expected_head) is None:
        raise ValueError("expected_head must be a lowercase SHA-256 digest")
    previous = initial
    start = int(setting(policy, "starting_sequence", 1, 1))
    previous_time = None
    for index, record in enumerate(rows, start):
        sequence = record["sequence"]
        if not isinstance(sequence, int) or isinstance(sequence, bool):
            raise ValueError("sequence must be an integer")
        event_time = timestamp(record["timestamp"])
        object_value(record["event"], "event")
        for field in ("hash", "previous_hash", "hmac"):
            if not isinstance(record[field], str) or re.fullmatch(r"[0-9a-f]{64}", record[field]) is None:
                raise ValueError("record hash and HMAC fields must be lowercase 64-character hexadecimal strings")
        failures = []
        if sequence != index:
            failures.append("sequence")
        if record["previous_hash"] != previous:
            failures.append("previous-hash")
        digest = hashlib.sha256(canonical_event(record)).hexdigest()
        if not hmac.compare_digest(record["hash"], digest):
            failures.append("content-hash")
        expected_hmac = hmac.new(key, record["hash"].encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(record["hmac"], expected_hmac):
            failures.append("hmac")
        if previous_time is not None and event_time < previous_time:
            failures.append("timestamp-order")
        if failures:
            result.append(finding("LEDGER-RECORD-INTEGRITY", "critical", str(index), "Audit record verification failed",
                                  {"failed_checks": failures}, "Preserve the export and compare against independently protected evidence."))
        previous, previous_time = digest, event_time
    if expected_head is not None and not hmac.compare_digest(previous, expected_head):
        result.append(finding("LEDGER-HEAD-MISMATCH", "critical", "ledger", "Calculated final head differs from the trusted anchor",
                              {"record_count": len(rows)}, "Investigate truncation, rewriting, incorrect anchors or a different export boundary."))
    return result


if __name__ == "__main__":
    raise SystemExit(main())
