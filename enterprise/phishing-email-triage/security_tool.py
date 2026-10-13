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
import email
import ipaddress
import re
from email import policy as email_policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlsplit

TOOL = "phishing-email-triage"
DESCRIPTION = "Triage bounded MIME email offline without opening attachments or fetching links."
DEMO = {"messages": [{"id": "synthetic-email", "trusted_authentication_boundary": False,
        "eml": "From: Example Support <support@example.com>\nReply-To: help@different.example\nTo: analyst@example.org\nSubject: Synthetic training message\nAuthentication-Results: forged.example; dmarc=fail\nContent-Type: text/plain; charset=utf-8\n\nReview https://portal.example@192.0.2.20/login\n"}]}


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.current = [], None

    def handle_starttag(self, tag, attributes):
        if tag.lower() == "a":
            href = dict(attributes).get("href")
            self.current = [href, ""] if href else None

    def handle_data(self, content):
        if self.current is not None:
            self.current[1] += content

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self.current is not None:
            self.links.append(tuple(self.current))
            self.current = None


def audit(data, policy, now):
    messages = unique_rows(records(data, "messages", ("id",)), "id")
    trusted = string_list(policy.get("trusted_authserv_ids", []), "trusted_authserv_ids")
    risky_extensions = string_list(policy.get("risky_attachment_extensions", [".exe", ".scr", ".js", ".vbs", ".ps1", ".docm", ".xlsm", ".lnk", ".iso"]), "risky_attachment_extensions")
    maximum_bytes = int(setting(policy, "maximum_message_bytes", 2 * 1024 * 1024, 1, 10 * 1024 * 1024))
    result = []
    for identifier, row in messages.items():
        if ("eml" in row) == ("path" in row):
            raise ValueError("each message requires exactly one of eml or path")
        boundary = boolean(row.get("trusted_authentication_boundary", False), "trusted_authentication_boundary")
        if "path" in row:
            path = Path(text(row["path"], "message.path"))
            if path.is_symlink():
                raise ValueError("email input must not be a symbolic link")
            with path.open("rb") as stream:
                content = stream.read(maximum_bytes + 1)
        else:
            content = text(row["eml"], "eml").encode()
        if len(content) > maximum_bytes:
            raise ValueError("email exceeds the configured inspection size")
        message = BytesParser(policy=email_policy.default).parsebytes(content)
        sender = parseaddr(str(message.get("From", "")))[1].rsplit("@", 1)[-1].lower()
        reply = parseaddr(str(message.get("Reply-To", "")))[1].rsplit("@", 1)[-1].lower()
        if sender and reply and sender != reply:
            result.append(finding("MAIL-REPLY-DOMAIN", "low", identifier, "Reply-To uses a different domain than From",
                                  {"from_domain": sender, "reply_domain": reply}, "Review the sender relationship and expected reply workflow."))
        for header in message.get_all("Authentication-Results", []):
            service = str(header).split(";", 1)[0].strip().lower()
            if not boundary or service not in [value.lower() for value in trusted]:
                result.append(finding("MAIL-AUTH-UNTRUSTED", "info", identifier, "Authentication results are outside the configured trust boundary",
                                      {"authserv_id": service}, "Use authentication evidence from a trusted receiver that strips attacker-supplied authentication headers.", subject=service))
                continue
            failures = re.findall(r"(?i)\b(spf|dkim|dmarc)\s*=\s*(fail|softfail|temperror|permerror)\b", str(header))
            if failures:
                result.append(finding("MAIL-AUTH-FAILURE", "high" if any(kind.lower() == "dmarc" and value.lower() == "fail" for kind, value in failures) else "medium",
                                      identifier, "Trusted receiver reports email-authentication problems",
                                      {"failures": failures, "authserv_id": service}, "Review alignment, forwarding and sender legitimacy using receiver evidence."))
        links, seen = [], set()
        for part in message.walk():
            filename = part.get_filename()
            if filename and Path(filename).suffix.lower() in risky_extensions:
                result.append(finding("MAIL-RISKY-ATTACHMENT", "high", identifier, "Attachment type requires isolated security review",
                                      {"filename": filename, "extension": Path(filename).suffix.lower()}, "Do not execute the attachment; use the organization's approved isolated analysis process.", subject=filename))
            if part.get_content_type() in {"text/plain", "text/html"} and part.get_content_disposition() != "attachment":
                try:
                    body = part.get_content()
                except (LookupError, UnicodeError, ValueError):
                    result.append(finding("MAIL-DECODE-GAP", "medium", identifier, "Text body could not be decoded",
                                          {"content_type": part.get_content_type()}, "Review the MIME encoding with a suitable offline parser."))
                    continue
                if not isinstance(body, str):
                    continue
                links.extend((value, "") for value in re.findall(r'''https?://[^\s<>"']+''', body))
                if part.get_content_type() == "text/html":
                    parser = LinkParser()
                    parser.feed(body)
                    links.extend(parser.links)
        for url, displayed in links:
            try:
                parsed = urlsplit(url.rstrip(".,;)"))
            except ValueError:
                if ("malformed", "url") not in seen:
                    seen.add(("malformed", "url"))
                    result.append(finding("MAIL-MALFORMED-URL", "medium", identifier, "Email contains a malformed URL",
                                          {"parse_error": True}, "Review the malformed destination offline without following the link."))
                continue
            host = parsed.hostname or ""
            if parsed.scheme not in {"http", "https"}:
                continue
            indicators = []
            if parsed.username is not None:
                indicators.append("userinfo-in-url")
            try:
                ipaddress.ip_address(host)
                indicators.append("ip-address-host")
            except ValueError:
                pass
            if any(label.lower().startswith("xn--") for label in host.split(".")) or not host.isascii():
                indicators.append("internationalized-host-review")
            visible_domain = displayed.strip().lower().removeprefix("https://").removeprefix("http://").split("/", 1)[0]
            if re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", visible_domain) and visible_domain != host.lower():
                indicators.append("displayed-domain-mismatch")
            for indicator in indicators:
                key = host, indicator
                if key in seen:
                    continue
                seen.add(key)
                result.append(finding("MAIL-SUSPICIOUS-URL", "medium" if indicator == "internationalized-host-review" else "high", identifier,
                                      "URL contains a phishing-relevant indicator", {"host": host, "indicator": indicator},
                                      "Verify the destination through a known trusted channel without following the email link.", subject=host + ":" + indicator))
    return result


if __name__ == "__main__":
    raise SystemExit(main())
