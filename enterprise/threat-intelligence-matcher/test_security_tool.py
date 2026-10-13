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

class IntelligenceTests(unittest.TestCase):
    def test_domain_boundary_not_substring(self):
        data = copy.deepcopy(tool.DEMO)
        data['observations'] = [{'id': 'x', 'kind': 'domain', 'value': 'notsuspicious.example'}]
        self.assertEqual(tool.audit(data, {}, NOW), [])

    def test_expired_and_low_confidence_ignored(self):
        data = copy.deepcopy(tool.DEMO)
        data['indicators'][0]['expires'] = '2025-01-01T00:00:00Z'
        data['indicators'][1]['confidence'] = 10
        self.assertEqual(tool.audit(data, {}, NOW), [])

    def test_exact_domain_without_subdomains(self):
        data = copy.deepcopy(tool.DEMO)
        data['indicators'][1]['include_subdomains'] = False
        data['observations'] = [data['observations'][1]]
        self.assertEqual(tool.audit(data, {}, NOW), [])

    def test_ipv6_cidr(self):
        data = copy.deepcopy(tool.DEMO)
        data['indicators'] = [{**data['indicators'][0], 'value': '2001:db8::/32'}]
        data['observations'] = [{'id': 'v6', 'kind': 'ip', 'value': '2001:db8:1::1'}]
        self.assertEqual(len(tool.audit(data, {}, NOW)), 1)

    def test_hash_matching_case_insensitive(self):
        data = copy.deepcopy(tool.DEMO)
        data['indicators'] = [{**data['indicators'][0], 'kind': 'sha256', 'value': 'A' * 64}]
        data['observations'] = [{'id': 'hash', 'kind': 'sha256', 'value': 'a' * 64}]
        self.assertEqual(len(tool.audit(data, {}, NOW)), 1)

    def test_invalid_indicator_rejected(self):
        data = copy.deepcopy(tool.DEMO)
        data['indicators'][0]['value'] = 'not-an-ip'
        with self.assertRaises(ValueError):
            tool.audit(data, {}, NOW)


if __name__ == "__main__":
    unittest.main()
