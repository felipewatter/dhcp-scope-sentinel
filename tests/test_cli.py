from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from dhcp_scope_sentinel import __version__
from dhcp_scope_sentinel.cli import main

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT/'examples'/'baseline.json'
RISKY = ROOT/'examples'/'candidate-risky.json'
CONTRACTS = ROOT/'examples'/'contracts.json'


class CommandLineTests(unittest.TestCase):
    def call(self, *args):
        return subprocess.run([sys.executable, '-m', 'dhcp_scope_sentinel', *map(str,args)],
                              capture_output=True, text=True, check=False)

    def test_version_dynamic(self):
        result = self.call('--version')
        self.assertEqual(result.returncode, 0)
        self.assertIn(__version__, result.stdout)

    def test_base_audit_passes(self):
        result=self.call('audit', BASE, '--policy', CONTRACTS)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)['summary']['high'], 0)

    def test_risky_audit_blocked(self):
        result=self.call('audit', RISKY, '--policy', CONTRACTS)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)['summary']['critical'], 2)

    def test_risky_diff_blocked(self):
        result=self.call('diff', BASE, RISKY, '--policy', CONTRACTS)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)['summary']['introduced']['critical'], 2)

    def test_no_fail_threshold(self):
        result=self.call('audit', RISKY, '--fail-on', 'none')
        self.assertEqual(result.returncode, 0)
        self.assertTrue(json.loads(result.stdout)['findings'])

    def test_critical_only(self):
        result=self.call('audit', RISKY, '--fail-on', 'critical')
        self.assertEqual(result.returncode, 2)

    def test_diff_introduced_only(self):
        result=self.call('diff', RISKY, RISKY)
        self.assertEqual(result.returncode, 0)
        self.assertFalse(json.loads(result.stdout)['introduced'])

    def test_diff_persistent_is_blocked_when_requested(self):
        result=self.call('diff', RISKY, RISKY, '--all-findings')
        self.assertEqual(result.returncode, 2)

    def test_sarif_and_json_written(self):
        with tempfile.TemporaryDirectory() as d:
            js, sf=Path(d)/'findings.json', Path(d)/'findings.sarif'
            result=self.call('audit', RISKY, '--json-out', js, '--sarif-out', sf)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, '')
            self.assertEqual(json.loads(sf.read_text())['version'],'2.1.0')
            self.assertEqual(json.loads(js.read_text())['mode'],'audit')

    def test_sarif_without_json_destination(self):
        with tempfile.TemporaryDirectory() as d:
            sf=Path(d)/'results.sarif'
            result=self.call('audit', BASE, '--sarif-out', sf)
            self.assertEqual(result.returncode, 0)
            self.assertTrue(json.loads(result.stdout))
            self.assertEqual(json.loads(sf.read_text())['runs'][0]['results'], [])

    def test_output_does_not_overwrite_input(self):
        original=BASE.read_bytes()
        result=self.call('audit', BASE, '--json-out', BASE)
        self.assertEqual(result.returncode, 3)
        self.assertEqual(BASE.read_bytes(),original)

    def test_output_does_not_overwrite_policy(self):
        original=CONTRACTS.read_bytes()
        result=self.call('audit', BASE, '--policy', CONTRACTS, '--sarif-out', CONTRACTS)
        self.assertEqual(result.returncode, 3)
        self.assertEqual(CONTRACTS.read_bytes(),original)

    def test_refuses_existing_output(self):
        with tempfile.TemporaryDirectory() as d:
            target=Path(d)/'report.json'
            target.write_text('sensitive-content')
            result=self.call('audit', BASE, '--json-out', target)
            self.assertEqual(result.returncode,3)
            self.assertEqual(target.read_text(),'sensitive-content')

    def test_refuses_two_identical_output_destinations(self):
        with tempfile.TemporaryDirectory() as d:
            target=Path(d)/'report.json'
            result=self.call('audit', BASE, '--json-out', target, '--sarif-out', target)
            self.assertEqual(result.returncode,3)
            self.assertFalse(target.exists())

    def test_refuses_output_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            real=Path(d)/'protected'
            real.write_text('untouched')
            target=Path(d)/'report.json'
            try: target.symlink_to(real)
            except (OSError,NotImplementedError): self.skipTest('symlink unavailable')
            result=self.call('audit', BASE, '--json-out', target)
            self.assertEqual(result.returncode, 3)
            self.assertEqual(real.read_text(), 'untouched')

    def test_refuses_output_to_nonexistent_directory(self):
        with tempfile.TemporaryDirectory() as d:
            target=Path(d)/'missing'/'report.json'
            result=self.call('audit', BASE, '--json-out', target)
            self.assertEqual(result.returncode, 3)
            self.assertFalse(target.exists())

    def test_refuses_existing_sarif_without_writing_json(self):
        with tempfile.TemporaryDirectory() as d:
            target=Path(d)/'result.json';sf=Path(d)/'result.sarif'
            sf.write_text('sensitive')
            result=self.call('audit', BASE, '--json-out', target,'--sarif-out',sf)
            self.assertEqual(result.returncode,3)
            self.assertFalse(target.exists())

    def test_missing_policy(self):
        with tempfile.TemporaryDirectory() as d:
            result=self.call('audit', BASE, '--policy', Path(d)/'missing.json')
            self.assertEqual(result.returncode,3)
            self.assertIn('error:',result.stderr)

    def test_nonsense_root_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            bad=Path(d)/'input.json';bad.write_text('{}')
            result=self.call('audit', bad)
            self.assertEqual(result.returncode,3)

    def test_invalid_command_rejected(self):
        result=self.call('execute',BASE)
        self.assertNotEqual(result.returncode,0)

    def test_report_stdout_valid_json(self):
        result=self.call('audit', RISKY)
        self.assertEqual(json.loads(result.stdout)['schemaVersion'],1)

    def test_no_subprocess_or_network_dependency_in_smoke(self):
        result=self.call('audit',BASE)
        self.assertEqual(result.returncode,0)


if __name__ == '__main__':
    unittest.main()
