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

class KubernetesTests(unittest.TestCase):
    def secure(self):
        return {'kind': 'List', 'items': [{'kind': 'Pod', 'metadata': {'name': 'app'}, 'spec': {
            'automountServiceAccountToken': False, 'securityContext': {'runAsNonRoot': True, 'runAsUser': 1000},
            'containers': [{'name': 'app', 'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True, 'capabilities': {'drop': ['ALL']}}}]}}]}

    def test_pod_context_inheritance(self):
        self.assertEqual(tool.audit(self.secure(), {}, NOW), [])

    def test_container_root_overrides_pod_user(self):
        data = self.secure()
        data['items'][0]['spec']['containers'][0]['securityContext']['runAsUser'] = 0
        self.assertIn('K8S-NONROOT', {x['rule'] for x in tool.audit(data, {}, NOW)})

    def test_namespace_exclusion(self):
        self.assertEqual(tool.audit(copy.deepcopy(tool.DEMO), {'excluded_namespaces': ['demo']}, NOW), [])

    def test_init_container_is_reviewed(self):
        data = self.secure()
        data['items'][0]['spec']['initContainers'] = [{'name': 'init', 'securityContext': {'privileged': True}}]
        self.assertIn('K8S-PRIVILEGED', {x['rule'] for x in tool.audit(data, {}, NOW)})

    def test_cronjob_spec_path(self):
        data = self.secure()
        spec = data['items'][0]['spec']
        data['items'][0].update(kind='CronJob', spec={'jobTemplate': {'spec': {'template': {'spec': spec}}}})
        self.assertEqual(tool.audit(data, {}, NOW), [])

    def test_boolean_validation(self):
        data = self.secure()
        data['items'][0]['spec']['hostNetwork'] = 'false'
        with self.assertRaises(ValueError):
            tool.audit(data, {}, NOW)


if __name__ == "__main__":
    unittest.main()
