"""Reproducible source ZIP and SHA256 manifest. Never includes VCS or machine files."""
from __future__ import annotations

import hashlib
import json
import sys
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWED_DIRS = ('src/', 'tests/', 'examples/', 'docs/', 'scripts/', '.github/')
ALLOWED_FILES = {'.gitignore', 'LICENSE', 'README.md', 'README.en.md', 'CHANGELOG.md',
                 'CONTRIBUTING.md', 'CODE_OF_CONDUCT.md', 'SECURITY.md', 'pyproject.toml'}
DISCARD = {'__pycache__', '.git', '.pytest_cache', 'dist', 'build', '.venv', 'venv'}


def selected(path: Path) -> bool:
    rel = path.relative_to(ROOT).as_posix()
    return (path.is_file() and not path.is_symlink()
            and not any(x in DISCARD or x.endswith('.egg-info') for x in path.relative_to(ROOT).parts)
            and not path.name.endswith(('.pyc', '.pyo', '.swp'))
            and (rel in ALLOWED_FILES or rel.startswith(ALLOWED_DIRS)))


def build(dest: Path) -> list[Path]:
    version = tomllib.loads((ROOT / 'pyproject.toml').read_text(encoding='utf-8'))['project']['version']
    dest.mkdir(parents=True, exist_ok=True)
    prefix = f'dhcp-scope-sentinel-v{version}'
    files = sorted((p for p in ROOT.rglob('*') if selected(p)), key=lambda x: x.relative_to(ROOT).as_posix())
    if not files or not any(p.name == 'LICENSE' for p in files):
        raise ValueError('missing mandatory distribution files')
    hashes: dict[str,str] = {}
    archive = dest / f'{prefix}-source.zip'
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zipobj:
        for path in files:
            rel = path.relative_to(ROOT).as_posix()
            content = path.read_bytes()
            hashes[rel] = hashlib.sha256(content).hexdigest()
            meta = zipfile.ZipInfo(f'{prefix}/{rel}', date_time=(2026, 11, 9, 0, 0, 0))
            meta.compress_type = zipfile.ZIP_DEFLATED
            meta.external_attr = 0o100644 << 16
            zipobj.writestr(meta, content, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    manifest = dest / f'{prefix}-manifest.json'
    manifest.write_text(json.dumps({'schema_version': 1, 'version': version, 'sha256': hashes}, sort_keys=True, indent=2)+'\n', encoding='utf-8')
    return [archive, manifest]


def checksum(dest: Path, artifacts: list[Path], version: str) -> Path:
    target = dest / f'dhcp-scope-sentinel-v{version}-SHA256SUMS.txt'
    target.write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n'
                              for p in sorted(artifacts, key=lambda p:p.name)), encoding='utf-8')
    return target


if __name__ == '__main__':
    destination = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / 'dist'
    entries = build(destination)
    ver = tomllib.loads((ROOT / 'pyproject.toml').read_text(encoding='utf-8'))['project']['version']
    # Release jobs may produce a wheel before calling this script. Include that artifact if present.
    wheels = list(destination.glob(f'dhcp_scope_sentinel-{ver}-*.whl'))
    entries.extend(wheels)
    sums = checksum(destination, entries, ver)
    for path in entries + [sums]:
        print(path)
