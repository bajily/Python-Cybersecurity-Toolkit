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

class LinuxTests(unittest.TestCase):
    def test_approved_shadow_group_read_is_not_world_read(self):
        data = {'sshd_config': '', 'sysctl': {}, 'files': [{'path': '/etc/shadow', 'mode': '0640', 'owner_uid': 0}]}
        self.assertEqual(tool.audit(data, {'ssh': {}, 'sysctl': {}}, NOW), [])
        self.assertIn('LINUX-SHADOW-READ', {x['rule'] for x in tool.audit(data, {'ssh': {}, 'sysctl': {}, 'allow_shadow_group_read': False}, NOW)})

    def test_first_global_value_wins(self):
        settings, review = tool.parse_sshd('PermitRootLogin no\nPermitRootLogin yes\n')
        self.assertEqual(settings['permitrootlogin'], 'no')

    def test_match_settings_not_treated_as_global(self):
        settings, review = tool.parse_sshd('PasswordAuthentication no\nMatch User legacy\nPasswordAuthentication yes\n')
        self.assertEqual(settings['passwordauthentication'], 'no')
        self.assertEqual(review[0]['directive'], 'match')

    def test_clean_baseline(self):
        data = {'sshd_config': 'PermitRootLogin no\nPasswordAuthentication no\nPermitEmptyPasswords no\nPubkeyAuthentication yes\n',
                'sysctl': {'kernel.randomize_va_space': '2', 'net.ipv4.conf.all.accept_redirects': '0', 'net.ipv4.conf.all.send_redirects': '0'},
                'files': [{'path': '/etc/shadow', 'mode': '0600', 'owner_uid': 0}]}
        self.assertEqual(tool.audit(data, {}, NOW), [])

    def test_unknown_ssh_value_is_not_assumed_safe(self):
        data = copy.deepcopy(tool.DEMO)
        data['sshd_config'] = ''
        self.assertIn('not-explicitly-set', json.dumps(tool.audit(data, {}, NOW)))

    def test_octal_validation(self):
        data = copy.deepcopy(tool.DEMO)
        data['files'][0]['mode'] = '0999'
        with self.assertRaises(ValueError):
            tool.audit(data, {}, NOW)

    def test_custom_host_role_policy(self):
        data = {'sshd_config': '', 'sysctl': {'net.ipv4.ip_forward': '1'}, 'files': []}
        self.assertEqual(tool.audit(data, {'ssh': {}, 'sysctl': {'net.ipv4.ip_forward': '1'}}, NOW), [])


if __name__ == "__main__":
    unittest.main()
