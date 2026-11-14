import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
from integration import vm_checks as vm


class VMWorkflowTests(unittest.TestCase):
    def test_namespace_probe_has_fixed_locale(self):
        with patch.object(sys, 'argv', ['vm_checks.py', '--fixtures-only']), patch.object(vm.os, 'geteuid', return_value=1000), patch.object(
            vm, 'ssh_workflow', return_value={'ssh': 'skipped'}
        ), patch.object(vm.shutil, 'which', return_value='/usr/bin/unshare'), patch.object(
            vm.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'Operation not permitted')
        ) as run, patch('builtins.print'):
            self.assertEqual(vm.main(), 77)
            self.assertEqual(run.call_args.kwargs['env']['LC_ALL'], 'C')

    def test_real_fixture_failure_is_not_masked_as_skip(self):
        with patch.object(sys, 'argv', ['vm_checks.py', '--fixtures-only']), patch.object(vm.os, 'geteuid', return_value=1000), patch.object(
            vm, 'ssh_workflow', return_value={'ssh': 'skipped'}
        ), patch.object(vm.shutil, 'which', return_value='/usr/bin/unshare'), patch.object(
            vm.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'fixture assertion failed')
        ):
            with self.assertRaisesRegex(RuntimeError, 'fixture assertion'):
                vm.main()

    def test_full_fixture_workflow_in_disposable_namespace(self):
        result = subprocess.run([sys.executable, 'integration/vm_checks.py', '--fixtures-only'], text=True, capture_output=True, timeout=120)
        if result.returncode == 77:self.skipTest('Namespaces de usuario no disponibles; integración privilegiada requiere VM/container descartable.')
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        data = json.loads(result.stdout)
        self.assertIn('passed', data['permissions'])
        if data.get('ssh') != 'skipped':self.assertIn('passed', data['ssh'])


if __name__ == '__main__':unittest.main()
