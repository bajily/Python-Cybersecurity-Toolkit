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

class ContainerTests(unittest.TestCase):
    def test_invalid_digest_does_not_satisfy_pinning(self):
        data = {'dockerfiles': [{'path': 'x', 'text': 'FROM python@sha256:bad\nUSER 1000\n'}]}
        self.assertIn('CONTAINER-IMAGE-PINNING', {x['rule'] for x in tool.audit(data, {}, NOW)})

    def test_secure_final_stage(self):
        data = {'dockerfiles': [{'path': 'Dockerfile', 'text': 'FROM python@sha256:' + 'a' * 64 + '\nUSER 1000\nCOPY app /app\n'}]}
        self.assertEqual(tool.audit(data, {}, NOW), [])

    def test_final_stage_not_builder_user(self):
        data = {'dockerfiles': [{'path': 'Dockerfile', 'text': 'FROM scratch AS builder\nUSER root\nFROM scratch\nUSER 1000\n'}]}
        self.assertEqual(tool.audit(data, {}, NOW), [])

    def test_stage_alias_inherits_user(self):
        data = {'dockerfiles': [{'path': 'Dockerfile', 'text': 'FROM scratch AS base\nUSER 1000\nFROM base\n'}]}
        self.assertEqual(tool.audit(data, {}, NOW), [])

    def test_continuation(self):
        rows = tool.docker_instructions('FROM scratch\nRUN echo one \\\n && echo two\nUSER 1000\n')
        self.assertEqual(rows[1][0], 'RUN')
        self.assertIn('echo two', rows[1][1])

    def test_secret_values_not_reported(self):
        self.assertNotIn('synthetic-value', json.dumps(tool.audit(copy.deepcopy(tool.DEMO), {}, NOW)))

    def test_missing_stage_rejected(self):
        with self.assertRaises(ValueError):
            tool.audit({'dockerfiles': [{'path': 'x', 'text': 'USER 1000'}]}, {}, NOW)


if __name__ == "__main__":
    unittest.main()
