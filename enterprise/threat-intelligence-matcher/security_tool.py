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
import ipaddress
import re

TOOL = "threat-intelligence-matcher"
DESCRIPTION = "Match local IP, CIDR, domain and SHA-256 indicators with expiry and provenance checks."
DEMO = {"indicators": [{"id": "synthetic-ioc-1", "kind": "cidr", "value": "192.0.2.0/24", "confidence": 90,
                        "expires": "2027-01-01T00:00:00Z", "source": "synthetic-training-feed"},
                       {"id": "synthetic-ioc-2", "kind": "domain", "value": "suspicious.example", "include_subdomains": True,
                        "confidence": 85, "expires": "2027-01-01T00:00:00Z", "source": "synthetic-training-feed"}],
        "observations": [{"id": "event-1", "kind": "ip", "value": "192.0.2.20"},
                         {"id": "event-2", "kind": "domain", "value": "api.suspicious.example"}]}


def domain_name(value):
    value = text(value, "domain").rstrip(".").encode("idna").decode().lower()
    if len(value) > 253 or any(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) is None for label in value.split(".")):
        raise ValueError("indicator domain must be a valid label-based hostname")
    return value


def sha256_value(value):
    if not isinstance(value, str) or re.fullmatch(r"[a-fA-F0-9]{64}", value) is None:
        raise ValueError("SHA-256 indicator must contain 64 hexadecimal characters")
    return value.lower()


def audit(data, policy, now):
    indicators = unique_rows(records(data, "indicators", ("id", "kind", "value", "confidence", "expires", "source")), "id")
    observations = unique_rows(records(data, "observations", ("id", "kind", "value")), "id")
    minimum_confidence = setting(policy, "minimum_confidence", 70, 0, 100)
    networks, domains, hashes = defaultdict(lambda: defaultdict(list)), defaultdict(list), defaultdict(list)
    for identifier, row in indicators.items():
        kind = row["kind"]
        confidence = number(row["confidence"], "confidence", 0, 100)
        expires = timestamp(row["expires"])
        text(row["source"], "source")
        if kind in {"ip", "cidr"}:
            network = ipaddress.ip_network(row["value"], strict=False)
        elif kind == "domain":
            normalized = domain_name(row["value"])
            boolean(row.get("include_subdomains", False), "include_subdomains")
        elif kind == "sha256":
            normalized = sha256_value(row["value"])
        else:
            raise ValueError("indicator kind must be ip, cidr, domain or sha256")
        if confidence < minimum_confidence or expires <= now:
            continue
        if kind in {"ip", "cidr"}:
            networks[network.version][(network.prefixlen, int(network.network_address))].append(row)
        elif kind == "domain":
            domains[normalized].append(row)
        else:
            hashes[normalized].append(row)
    result = []
    for identifier, observation in observations.items():
        kind, value = observation["kind"], observation["value"]
        matches = []
        if kind == "ip":
            address = ipaddress.ip_address(value)
            bits = address.max_prefixlen
            integer = int(address)
            for prefix in range(bits, -1, -1):
                masked = (integer >> (bits - prefix)) << (bits - prefix) if prefix else 0
                matches.extend(networks[address.version].get((prefix, masked), []))
        elif kind == "domain":
            normalized = domain_name(value)
            labels = normalized.split(".")
            for index in range(len(labels)):
                candidate = ".".join(labels[index:])
                matches.extend(row for row in domains.get(candidate, []) if index == 0 or row.get("include_subdomains", False))
        elif kind == "sha256":
            matches = hashes.get(sha256_value(value), [])
        else:
            raise ValueError("observation kind must be ip, domain or sha256")
        for row in sorted(matches, key=lambda item: (-item["confidence"], item["id"])):
            result.append(finding("IOC-CORRELATION", "high" if row["confidence"] >= 90 else "medium", identifier,
                                  "Observation matches an active local indicator",
                                  {"indicator_id": row["id"], "kind": row["kind"], "confidence": row["confidence"],
                                   "source": row["source"], "expires": row["expires"]},
                                  "Validate source quality, shared infrastructure and related activity before deciding on response.", subject=row["id"]))
    return result


if __name__ == "__main__":
    raise SystemExit(main())
