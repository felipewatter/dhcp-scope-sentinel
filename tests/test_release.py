from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from dhcp_scope_sentinel import __version__

ROOT = Path(__file__).resolve().parents[1]


class ReleaseTests(unittest.TestCase):
    def make(self, folder: Path):
        import importlib.util
        spec = importlib.util.spec_from_file_location('build_release_script', ROOT/'scripts/build_release.py')
        mod = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(mod)
        files = mod.build(folder)
        checksum = mod.checksum(folder, files, __version__)
        return files[0], files[1], checksum

    def test_manifest_matches_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive, manifest, _ = self.make(Path(tmp))
            data = json.loads(manifest.read_text())
            self.assertEqual(data['version'], __version__)
            with zipfile.ZipFile(archive) as z:
                self.assertEqual(len(z.namelist()), len(data['sha256']))
                for entry in z.namelist():
                    rel = entry.split('/', 1)[1]
                    self.assertEqual(hashlib.sha256(z.read(entry)).hexdigest(), data['sha256'][rel])

    def test_checksum_matches(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive, manifest, checksums = self.make(Path(tmp))
            mapping = dict((name, digest) for digest, name in
                           (line.split('  ',1) for line in checksums.read_text().splitlines()))
            self.assertEqual(mapping[archive.name], hashlib.sha256(archive.read_bytes()).hexdigest())
            self.assertEqual(mapping[manifest.name], hashlib.sha256(manifest.read_bytes()).hexdigest())

    def test_source_archive_reproducible(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            first = self.make(Path(a)); second = self.make(Path(b))
            self.assertEqual([hashlib.sha256(x.read_bytes()).hexdigest() for x in first],
                             [hashlib.sha256(x.read_bytes()).hexdigest() for x in second])

    def test_no_cache_or_machine_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive, _, _ = self.make(Path(tmp))
            with zipfile.ZipFile(archive) as z:
                self.assertFalse(any(x in p for p in z.namelist() for x in ('__pycache__', '.git/', '.egg-info', '.env', 'dist/', 'build/')))

    def test_mandatory_docs_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive, _, _ = self.make(Path(tmp))
            prefix=f'dhcp-scope-sentinel-v{__version__}/'
            with zipfile.ZipFile(archive) as z:
                found=set(z.namelist())
                for rel in ('README.md','README.en.md','LICENSE','SECURITY.md',
                            'docs/THREAT_MODEL.md','docs/ARCHITECTURE.md','pyproject.toml',
                            '.github/workflows/ci.yml','.github/workflows/release.yml'):
                    self.assertIn(prefix+rel, found)

    def test_release_builder_does_not_write_to_input_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            before = set(ROOT.rglob('*.py'))
            self.make(Path(tmp))
            after = set(ROOT.rglob('*.py'))
            self.assertEqual(before, after)
