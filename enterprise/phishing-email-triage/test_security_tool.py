import copy
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import security_tool as tool

NOW = datetime(2026, 10, 13, 12, tzinfo=timezone.utc)


class ReportingTests(unittest.TestCase):
    def test_demo_generates_explainable_findings(self):
        results = tool.audit(copy.deepcopy(tool.DEMO), {}, NOW)
        self.assertTrue(results)
        self.assertTrue(all(item['remediation'] and item['evidence'] for item in results))

    def test_fingerprints_are_deterministic(self):
        self.assertEqual(tool.audit(copy.deepcopy(tool.DEMO), {}, NOW),
                         tool.audit(copy.deepcopy(tool.DEMO), {}, NOW))

    def test_active_and_expired_suppressions(self):
        rows = tool.audit(copy.deepcopy(tool.DEMO), {}, NOW)
        item = {'fingerprint': rows[0]['fingerprint'], 'reason': 'Synthetic exception review',
                'expires': '2027-01-01T00:00:00Z'}
        self.assertEqual(len(tool.build_report(rows, [item], NOW)['suppressed']), 1)
        item['expires'] = '2026-01-01T00:00:00Z'
        self.assertEqual(len(tool.build_report(rows, [item], NOW)['suppressed']), 0)

    def test_invalid_exception_and_input(self):
        with self.assertRaises(ValueError):
            tool.build_report([], [{'fingerprint': 'x', 'reason': '', 'expires': 'bad'}], NOW)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            tool.audit({}, {}, NOW)
        duplicate = {'fingerprint': 'same', 'reason': 'Synthetic test exception', 'expires': '2027-01-01T00:00:00Z'}
        with self.assertRaises(ValueError):
            tool.build_report([], [duplicate, duplicate], NOW)

    def test_json_ambiguity_rejected(self):
        for content in ['{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}']:
            with self.assertRaises(ValueError):
                tool.decode_json(content)

    def test_sarif_contains_rules_and_stable_fingerprints(self):
        report = tool.build_report(tool.audit(copy.deepcopy(tool.DEMO), {}, NOW), now=NOW)
        result = tool.sarif(report)
        self.assertEqual(result['version'], '2.1.0')
        self.assertEqual(len(result['runs'][0]['results']), len(report['findings']))
        self.assertTrue(all(x['partialFingerprints'] for x in result['runs'][0]['results']))

    def test_cli_demo_and_missing_input(self):
        script = Path(__file__).with_name('security_tool.py')
        result = subprocess.run([sys.executable, str(script), '--demo', '--now', NOW.isoformat()],
                                capture_output=True, text=True)
        self.assertIn(result.returncode, [0, 1], result.stderr)
        self.assertEqual(json.loads(result.stdout)['tool'], tool.TOOL)
        result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)

class EmailTests(unittest.TestCase):
    def test_malformed_url_becomes_a_finding(self):
        data = {'messages': [{'id': 'malformed', 'eml': 'From: a@example.com\nContent-Type: text/plain\n\nhttps://[not-an-ip]/login'}]}
        self.assertIn('MAIL-MALFORMED-URL', {x['rule'] for x in tool.audit(data, {}, NOW)})

    def test_url_userinfo_and_ip_host(self):
        encoded = json.dumps(tool.audit(copy.deepcopy(tool.DEMO), {}, NOW))
        self.assertIn('userinfo-in-url', encoded)
        self.assertIn('ip-address-host', encoded)

    def test_forged_authentication_header_not_trusted(self):
        rows = tool.audit(copy.deepcopy(tool.DEMO), {'trusted_authserv_ids': ['forged.example']}, NOW)
        self.assertNotIn('MAIL-AUTH-FAILURE', {x['rule'] for x in rows})

    def test_receiver_boundary_required(self):
        data = copy.deepcopy(tool.DEMO)
        data['messages'][0]['trusted_authentication_boundary'] = True
        rows = tool.audit(data, {'trusted_authserv_ids': ['forged.example']}, NOW)
        self.assertIn('MAIL-AUTH-FAILURE', {x['rule'] for x in rows})

    def test_clean_plain_message(self):
        data = {'messages': [{'id': 'safe', 'eml': 'From: a@example.com\nTo: b@example.com\nContent-Type: text/plain\n\nHello team.\n'}]}
        self.assertEqual(tool.audit(data, {}, NOW), [])

    def test_html_display_mismatch(self):
        data = {'messages': [{'id': 'html', 'eml': 'From: a@example.com\nContent-Type: text/html\n\n<a href="https://different.example/">portal.example</a>'}]}
        self.assertIn('displayed-domain-mismatch', json.dumps(tool.audit(data, {}, NOW)))

    def test_size_limit(self):
        with self.assertRaises(ValueError):
            tool.audit(copy.deepcopy(tool.DEMO), {'maximum_message_bytes': 5}, NOW)


if __name__ == "__main__":
    unittest.main()
