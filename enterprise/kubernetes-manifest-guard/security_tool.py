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
TOOL = "kubernetes-manifest-guard"
DESCRIPTION = "Audit Kubernetes workload security contexts and host-access settings in JSON manifests."
DEMO = {"resources": [{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "synthetic-api", "namespace": "demo"},
                       "spec": {"template": {"spec": {"hostNetwork": True, "containers": [{"name": "api", "image": "synthetic:latest",
                                 "securityContext": {"privileged": True, "capabilities": {"add": ["SYS_ADMIN"]}}}]}}}}]}


def pod_spec(resource):
    kind = resource.get("kind")
    if kind == "Pod":
        return object_value(resource.get("spec"), "Pod.spec")
    if kind in {"Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job"}:
        return object_value(resource.get("spec", {}).get("template", {}).get("spec"), "workload.template.spec")
    if kind == "CronJob":
        return object_value(resource.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec"), "CronJob.template.spec")
    return None


def audit(data, policy, now):
    object_value(data)
    resources = records(data, "items") if data.get("kind") == "List" else records(data, "resources")
    excluded = string_list(policy.get("excluded_namespaces", []), "excluded_namespaces")
    dangerous_caps = string_list(policy.get("dangerous_capabilities", ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "DAC_OVERRIDE"]), "dangerous_capabilities")
    result = []
    for resource in resources:
        metadata = object_value(resource.get("metadata"), "metadata")
        name = text(metadata.get("name"), "metadata.name")
        namespace = text(metadata.get("namespace", "default"), "namespace")
        if namespace in excluded:
            continue
        base = namespace + "/" + str(resource.get("kind")) + "/" + name
        spec = pod_spec(resource)
        if spec is None:
            result.append(finding("K8S-UNREVIEWED-KIND", "info", base, "Resource kind is outside workload security-context review",
                                  {"kind": resource.get("kind")}, "Use a policy covering this Kubernetes resource kind."))
            continue
        pod_context = object_value(spec.get("securityContext", {}), "pod.securityContext")
        for field in ("hostNetwork", "hostPID", "hostIPC"):
            if boolean(spec.get(field, False), field):
                result.append(finding("K8S-HOST-NAMESPACE", "high", base, "Workload requests a host namespace",
                                      {"field": field}, "Remove host namespace access or document and independently review the necessity.", subject=field))
        if boolean(spec.get("automountServiceAccountToken", True), "automountServiceAccountToken"):
            result.append(finding("K8S-SERVICE-ACCOUNT-TOKEN", "medium", base, "Token automount is not disabled in the workload",
                                  {"workload_automount": spec.get("automountServiceAccountToken", "unset")},
                                  "Disable token mounting when unnecessary; verify service-account defaults and RBAC."))
        volumes = spec.get("volumes", [])
        if not isinstance(volumes, list):
            raise ValueError("volumes must be an array")
        if any(isinstance(volume, dict) and "hostPath" in volume for volume in volumes):
            result.append(finding("K8S-HOSTPATH", "high", base, "Workload includes hostPath storage",
                                  {"host_path_volume_count": sum(isinstance(volume, dict) and "hostPath" in volume for volume in volumes)},
                                  "Use scoped storage abstractions and review any required host filesystem access."))
        containers = records(spec, "containers", ("name",))
        if not containers:
            raise ValueError("workload must include a container")
        for category in ("initContainers", "ephemeralContainers"):
            if category in spec:
                containers = containers + records(spec, category, ("name",))
        unique_rows(containers, "name")
        for container in containers:
            identifier = base + "/" + text(container["name"], "container.name")
            context = object_value(container.get("securityContext", {}), "container.securityContext")
            if boolean(context.get("privileged", False), "privileged"):
                result.append(finding("K8S-PRIVILEGED", "critical", identifier, "Container requests privileged execution",
                                      {"privileged": True}, "Remove privileged execution and review workload isolation."))
            nonroot = context.get("runAsNonRoot", pod_context.get("runAsNonRoot"))
            user = context.get("runAsUser", pod_context.get("runAsUser"))
            if nonroot is not None:
                boolean(nonroot, "runAsNonRoot")
            if user is not None:
                number(user, "runAsUser", 0)
                if not isinstance(user, int):
                    raise ValueError("runAsUser must be an integer")
            if nonroot is not True or user == 0:
                result.append(finding("K8S-NONROOT", "high", identifier, "Non-root execution is not consistently declared",
                                      {"runAsNonRoot": nonroot, "runAsUser": user}, "Declare and validate a compatible non-root user and runAsNonRoot policy."))
            if boolean(context.get("allowPrivilegeEscalation", True), "allowPrivilegeEscalation"):
                result.append(finding("K8S-PRIVILEGE-ESCALATION", "high", identifier, "Privilege escalation is not disabled",
                                      {"value": context.get("allowPrivilegeEscalation", "unset")}, "Set allowPrivilegeEscalation false and test application compatibility."))
            if not boolean(context.get("readOnlyRootFilesystem", False), "readOnlyRootFilesystem"):
                result.append(finding("K8S-READONLY-ROOT", "medium", identifier, "Container root filesystem is not declared read-only",
                                      {"value": context.get("readOnlyRootFilesystem", "unset")}, "Use a read-only root filesystem and explicit writable volumes."))
            caps = object_value(context.get("capabilities", {}), "capabilities")
            added = string_list(caps.get("add", []), "capabilities.add")
            dropped = string_list(caps.get("drop", []), "capabilities.drop")
            if "ALL" not in dropped:
                result.append(finding("K8S-CAPABILITY-DROP", "medium", identifier, "Container does not drop all default capabilities",
                                      {"dropped": dropped}, "Drop ALL and explicitly add only reviewed required capabilities."))
            dangerous = sorted(set(added) & set(dangerous_caps))
            if dangerous:
                result.append(finding("K8S-DANGEROUS-CAPABILITY", "high", identifier, "Container adds sensitive Linux capabilities",
                                      {"capabilities": dangerous}, "Remove unnecessary capabilities and review workload access boundaries."))
    return result


if __name__ == "__main__":
    raise SystemExit(main())
