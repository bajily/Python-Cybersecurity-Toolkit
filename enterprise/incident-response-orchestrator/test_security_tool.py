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

class PlaybookTests(unittest.TestCase):
    def test_changed_approval_requirement_changes_checkpoint_key(self):
        step = copy.deepcopy(tool.DEMO['steps'][0])
        before = tool.step_key('incident', step)
        step['requires_approval'] = True
        self.assertNotEqual(before, tool.step_key('incident', step))

    def test_topological_order(self):
        steps = {x['id']: x for x in tool.DEMO['steps']}
        self.assertEqual(tool.step_order(steps), ['open-case', 'isolate-host'])

    def test_cycles_rejected(self):
        data = copy.deepcopy(tool.DEMO)
        data['steps'][0]['depends_on'] = ['isolate-host']
        with self.assertRaises(ValueError):
            tool.audit(data, {}, NOW)

    def test_forced_gate_cannot_be_disabled_for_containment(self):
        data = copy.deepcopy(tool.DEMO)
        data['steps'][1]['requires_approval'] = False
        self.assertIn('IR-APPROVAL-REQUIRED', {x['rule'] for x in tool.audit(data, {}, NOW)})

    def test_expired_approval_ignored(self):
        data = copy.deepcopy(tool.DEMO)
        data['approvals'] = [{'step_id': 'isolate-host', 'incident_id': data['incident']['id'], 'approved_by': 'synthetic-reviewer', 'expires': '2025-01-01T00:00:00Z'}]
        self.assertIn('IR-APPROVAL-REQUIRED', {x['rule'] for x in tool.audit(data, {}, NOW)})

    def test_matching_checkpoint_skipped(self):
        data = copy.deepcopy(tool.DEMO)
        data['previous_execution'] = [{'step_id': 'open-case', 'incident_id': data['incident']['id'], 'status': 'completed', 'idempotency_key': tool.step_key(data['incident']['id'], data['steps'][0])}]
        self.assertIn('already-completed-idempotent-skip', json.dumps(tool.audit(data, {}, NOW)))

    def test_changed_parameters_invalidate_checkpoint(self):
        data = copy.deepcopy(tool.DEMO)
        key = tool.step_key(data['incident']['id'], data['steps'][0])
        data['steps'][0]['parameters']['queue'] = 'other'
        data['previous_execution'] = [{'step_id': 'open-case', 'incident_id': data['incident']['id'], 'status': 'completed', 'idempotency_key': key}]
        self.assertIn('IR-CHECKPOINT-MISMATCH', {x['rule'] for x in tool.audit(data, {}, NOW)})

    def test_never_claims_to_execute_system_actions(self):
        plans = [x for x in tool.audit(copy.deepcopy(tool.DEMO), {}, NOW) if x['rule'] == 'IR-STEP-PLAN']
        self.assertTrue(all(x['evidence']['performed_system_action'] is False for x in plans))


if __name__ == "__main__":
    unittest.main()
