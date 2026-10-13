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
TOOL = "incident-response-orchestrator"
DESCRIPTION = "Validate incident playbook dependencies, approval gates and idempotent planning checkpoints."
DEMO = {"incident": {"id": "SYNTHETIC-INCIDENT-001", "severity": "high"},
        "steps": [{"id": "open-case", "action": "open_case", "depends_on": [], "requires_approval": False, "parameters": {"queue": "soc"}},
                  {"id": "isolate-host", "action": "isolate_host", "depends_on": ["open-case"], "requires_approval": True, "parameters": {"host": "synthetic-workstation"}}],
        "approvals": [], "previous_execution": []}
ALLOWED_ACTIONS = {"collect_evidence", "open_case", "notify_owner", "request_approval", "isolate_host"}
CONSEQUENTIAL_ACTIONS = {"isolate_host"}


def step_key(incident_id, step):
    value = json.dumps([incident_id, step], sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(value.encode()).hexdigest()


def step_order(steps):
    incoming = {identifier: len(step["depends_on"]) for identifier, step in steps.items()}
    children = defaultdict(list)
    for identifier, step in steps.items():
        for parent in step["depends_on"]:
            if parent not in steps:
                raise ValueError("playbook references an unknown dependency")
            children[parent].append(identifier)
    queue = deque(sorted(identifier for identifier, count in incoming.items() if count == 0))
    order = []
    while queue:
        identifier = queue.popleft()
        order.append(identifier)
        for child in sorted(children[identifier]):
            incoming[child] -= 1
            if incoming[child] == 0:
                queue.append(child)
    if len(order) != len(steps):
        raise ValueError("playbook dependency graph contains a cycle")
    return order


def audit(data, policy, now):
    incident = object_value(data.get("incident"), "incident")
    incident_id = text(incident.get("id"), "incident.id")
    if incident.get("severity") not in SEVERITIES:
        raise ValueError("unsupported incident severity")
    steps = unique_rows(records(data, "steps", ("id", "action", "depends_on", "requires_approval", "parameters")), "id")
    approvals = records(data, "approvals", ("step_id", "incident_id", "approved_by", "expires"))
    history = records(data, "previous_execution", ("step_id", "incident_id", "status", "idempotency_key"))
    for step in steps.values():
        string_list(step["depends_on"], "depends_on")
        if len(set(step["depends_on"])) != len(step["depends_on"]):
            raise ValueError("dependency entries must be unique")
        boolean(step["requires_approval"], "requires_approval")
        object_value(step["parameters"], "parameters")
        if step["action"] not in ALLOWED_ACTIONS:
            raise ValueError("playbook action is outside the explicit planning allowlist")
        if step.get("minimum_severity", "info") not in SEVERITIES:
            raise ValueError("invalid minimum_severity")
    valid_approvals = {}
    for row in approvals:
        text(row["approved_by"], "approved_by")
        if row["incident_id"] == incident_id and row["step_id"] not in steps:
            raise ValueError("approval references an unknown step")
        expires = timestamp(row["expires"])
        if row["incident_id"] == incident_id and expires > now:
            valid_approvals[row["step_id"]] = row["approved_by"]
    completed, mismatched, checkpoint_ids = set(), set(), set()
    for row in history:
        if row["status"] not in {"completed", "failed", "pending"}:
            raise ValueError("unsupported execution status")
        if row["incident_id"] != incident_id:
            continue
        identifier = row["step_id"]
        if identifier not in steps:
            raise ValueError("execution checkpoint references an unknown step")
        if identifier in checkpoint_ids:
            raise ValueError("current execution checkpoints must be unique per step")
        checkpoint_ids.add(identifier)
        if row["idempotency_key"] != step_key(incident_id, steps[identifier]):
            mismatched.add(identifier)
        elif row["status"] == "completed":
            completed.add(identifier)
    result = []
    for identifier in step_order(steps):
        step = steps[identifier]
        if identifier in mismatched:
            result.append(finding("IR-CHECKPOINT-MISMATCH", "high", identifier, "Execution checkpoint does not match the current step definition",
                                  {"incident": incident_id}, "Review changed parameters and invalidate stale checkpoints before approving work."))
            completed.discard(identifier)
        if identifier in completed:
            state = "already-completed-idempotent-skip"
        elif SEVERITIES[incident["severity"]] < SEVERITIES[step.get("minimum_severity", "info")]:
            state = "condition-not-met"
        else:
            approval_needed = step["requires_approval"] or step["action"] in CONSEQUENTIAL_ACTIONS
            if approval_needed and identifier not in valid_approvals:
                result.append(finding("IR-APPROVAL-REQUIRED", "high", identifier, "Response step requires a current incident-specific approval",
                                      {"incident": incident_id, "action": step["action"]}, "Obtain a time-limited approval from the appropriate incident owner."))
                state = "awaiting-approval"
            elif any(parent not in completed for parent in step["depends_on"]):
                state = "awaiting-completed-dependencies"
            else:
                state = "ready-for-operator"
        result.append(finding("IR-STEP-PLAN", "info", identifier, "Response workflow planning state",
                              {"incident": incident_id, "action": step["action"], "state": state,
                               "idempotency_key": step_key(incident_id, step), "performed_system_action": False},
                              "Use the approved operational system to carry out the reviewed step; this tool performs no external action."))
    return result


if __name__ == "__main__":
    raise SystemExit(main())
