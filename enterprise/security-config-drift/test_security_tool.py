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

class DriftTests(unittest.TestCase):
    def test_nested_secret_values_redacted(self):
        encoded = json.dumps(tool.audit(copy.deepcopy(tool.DEMO), {}, NOW))
        self.assertNotIn('synthetic-old', encoded)
        self.assertNotIn('synthetic-new', encoded)

    def test_identical_snapshot(self):
        data = copy.deepcopy(tool.DEMO)
        data['after'] = copy.deepcopy(data['before'])
        self.assertEqual(tool.audit(data, {}, NOW), [])

    def test_type_change_true_to_one_detected(self):
        self.assertTrue(tool.audit({'before': {'x': True}, 'after': {'x': 1}}, {}, NOW))

    def test_unordered_list_explicitly_configured(self):
        data = {'before': {'members': ['a', 'b']}, 'after': {'members': ['b', 'a']}}
        self.assertEqual(tool.audit(data, {'unordered_list_paths': ['/members']}, NOW), [])
        self.assertTrue(tool.audit(data, {}, NOW))

    def test_ignored_path(self):
        data = {'before': {'meta': {'generated_at': 1}}, 'after': {'meta': {'generated_at': 2}}}
        self.assertEqual(tool.audit(data, {}, NOW), [])

    def test_nested_secrets_in_unordered_objects_redacted(self):
        data = {'before': {'users': [{'password': 'old-sensitive'}]}, 'after': {'users': [{'password': 'new-sensitive'}]}}
        encoded = json.dumps(tool.audit(data, {'unordered_list_paths': ['/users']}, NOW))
        self.assertNotIn('old-sensitive', encoded)
        self.assertNotIn('new-sensitive', encoded)

    def test_json_pointer_key_escaping(self):
        self.assertIn('/a~1b~0c', tool.flatten({'a/b~c': 1}))


if __name__ == "__main__":
    unittest.main()
