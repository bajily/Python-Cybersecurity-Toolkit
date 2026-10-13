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

class WindowsTests(unittest.TestCase):
    def test_compliant_control_export(self):
        data = {'endpoints': [{'id': 'host', 'controls': copy.deepcopy(tool.DEFAULT_CONTROLS)}]}
        self.assertEqual(tool.audit(data, {}, NOW), [])

    def test_missing_evidence_is_reported(self):
        data = {'endpoints': [{'id': 'host', 'controls': {}}]}
        rows = tool.audit(data, {}, NOW)
        self.assertTrue(all(x['rule'] == 'WINDOWS-EVIDENCE-GAP' for x in rows))

    def test_disabled_firewall_is_high(self):
        data = {'endpoints': [{'id': 'host', 'controls': copy.deepcopy(tool.DEFAULT_CONTROLS)}]}
        data['endpoints'][0]['controls']['firewall_public'] = False
        self.assertEqual(tool.audit(data, {}, NOW)[0]['severity'], 'high')

    def test_string_false_not_accepted(self):
        data = copy.deepcopy(tool.DEMO)
        data['endpoints'][0]['controls']['firewall_domain'] = 'false'
        with self.assertRaises(ValueError):
            tool.audit(data, {}, NOW)

    def test_role_specific_baseline(self):
        data = {'endpoints': [{'id': 'host', 'controls': {'rdp_nla_required': False}}]}
        self.assertEqual(tool.audit(data, {'controls': {'rdp_nla_required': False}}, NOW), [])

    def test_duplicate_host_rejected(self):
        data = copy.deepcopy(tool.DEMO)
        data['endpoints'] *= 2
        with self.assertRaises(ValueError):
            tool.audit(data, {}, NOW)


if __name__ == "__main__":
    unittest.main()
