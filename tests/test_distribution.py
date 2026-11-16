import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile
from tools.build_distribution import build, verify, MODULES, ARTIFACT

ROOT = Path(__file__).resolve().parents[1]


class DistributionTests(unittest.TestCase):
    def test_reproducible_and_allowlisted(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = build(ROOT, directory)
            first = artifact.read_bytes()
            self.assertTrue(verify(directory))
            self.assertEqual(build(ROOT, directory).read_bytes(), first)
            with zipfile.ZipFile(artifact) as archive:
                self.assertEqual(set(archive.namelist()), set(MODULES) | {'__main__.py'})

    def test_self_contained_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = build(ROOT, directory)
            result = subprocess.run([sys.executable, str(artifact), '--version'], cwd=directory, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('0.15.0', result.stdout)
            result = subprocess.run([sys.executable, str(artifact), '--help'], cwd=directory, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('--extended', result.stdout)

    def test_tampering_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = build(ROOT, directory)
            with artifact.open('ab') as stream: stream.write(b'tamper')
            with self.assertRaises(ValueError): verify(directory)

    def test_manifest_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            build(ROOT, directory)
            (Path(directory)/'SHA256SUMS').write_text('0'*64 + '  ../../outside\n')
            with self.assertRaises(ValueError): verify(directory)

    def test_symlink_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); outside=root/'outside'; outside.write_text('unchanged')
            (root/ARTIFACT).symlink_to(outside)
            with self.assertRaises(ValueError): build(ROOT, root)
            self.assertEqual(outside.read_text(), 'unchanged')
