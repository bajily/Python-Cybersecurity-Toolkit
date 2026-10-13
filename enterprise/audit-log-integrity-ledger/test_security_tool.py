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

from unittest.mock import patch


class LedgerTests(unittest.TestCase):
    def valid(self):
        row = tool.sign_record({'sequence': 1, 'previous_hash': '0' * 64, 'timestamp': NOW.isoformat(), 'event': {'action': 'synthetic'}}, tool.DEMO_KEY)
        return {'key_env': '__DEMONSTRATION_ONLY__', 'records': [row], 'expected_head': row['hash']}

    def test_valid_chain_has_no_integrity_failure(self):
        rules = {x['rule'] for x in tool.audit(self.valid(), {}, NOW)}
        self.assertEqual(rules, {'LEDGER-DEMONSTRATION-KEY'})

    def test_payload_mutation_detected(self):
        data = self.valid()
        data['records'][0]['event']['action'] = 'changed'
        self.assertIn('LEDGER-RECORD-INTEGRITY', {x['rule'] for x in tool.audit(data, {}, NOW)})

    def test_truncation_detected_by_anchor(self):
        data = self.valid()
        data['records'] = []
        self.assertIn('LEDGER-HEAD-MISMATCH', {x['rule'] for x in tool.audit(data, {}, NOW)})

    def test_wrong_hmac_detected(self):
        data = self.valid()
        data['records'][0]['hmac'] = '0' * 64
        rows = tool.audit(data, {}, NOW)
        self.assertIn('hmac', json.dumps(rows))

    def test_missing_anchor_never_reported_as_trusted(self):
        data = self.valid()
        data.pop('expected_head')
        self.assertIn('LEDGER-TRUSTED-ANCHOR', {x['rule'] for x in tool.audit(data, {}, NOW)})

    def test_real_key_is_not_exposed(self):
        data = self.valid()
        data['key_env'] = 'SYNTHETIC_LEDGER_TEST_KEY'
        with patch.dict(tool.os.environ, {'SYNTHETIC_LEDGER_TEST_KEY': 'x' * 40}):
            encoded = json.dumps(tool.audit(data, {}, NOW))
        self.assertNotIn('x' * 40, encoded)


if __name__ == "__main__":
    unittest.main()
