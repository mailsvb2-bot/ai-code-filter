from pathlib import Path
import zipfile

import pytest

from ai_code_filter.integrity import audit_file_integrity, parse_manifest
from ai_code_filter.release.audit import audit_release

GOOD = 'a' * 64


def _manifest(tmp_path: Path, rel: str) -> Path:
    p = tmp_path / 'MANIFEST.sha256'
    p.write_text(f'{GOOD}  {rel}  size=1\n', encoding='utf-8')
    return p


@pytest.mark.parametrize('rel', [
    'CON.txt',
    'NUL',
    'COM1.txt',
    'LPT9.log',
    'dir/file:stream.txt',
    'dir/trailingdot.',
    'dir/trailingspace ',
    'dir/%2e%2e/evil.txt',
    'dir/evil%5cname.txt',
    'dir/\u202eevil.txt',
    'dir/' + ('a' * 121) + '.txt',
])
def test_manifest_rejects_portability_bypass_paths(tmp_path: Path, rel: str) -> None:
    with pytest.raises(ValueError):
        parse_manifest(_manifest(tmp_path, rel))


@pytest.mark.parametrize('rel', [
    'CON.txt',
    'dir/file:stream.txt',
    'dir/trailingdot.',
    'dir/trailingspace ',
    'dir/%2e%2e/evil.txt',
    'dir/\u202eevil.txt',
])
def test_tree_integrity_flags_unsafe_release_paths(tmp_path: Path, rel: str) -> None:
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('x\n', encoding='utf-8')
    report = audit_file_integrity(tmp_path)
    assert any(issue.category.startswith('PATH003') for issue in report.issues)


@pytest.mark.parametrize('name', [
    'pkg/CON.txt',
    'pkg/file:stream.txt',
    'pkg/trailingdot.',
    'pkg/trailingspace ',
    'pkg/%2e%2e/evil.txt',
    'pkg/a//b.txt',
    'pkg/\u202eevil.txt',
])
def test_zip_rejects_portability_bypass_member_names(tmp_path: Path, name: str) -> None:
    zp = tmp_path / 'bad.zip'
    with zipfile.ZipFile(zp, 'w') as zf:
        zf.writestr(name, b'x')
    report = audit_release(zp, run_cli_matrix=False)
    assert any(issue.category.startswith('ARCHIVE006') for issue in report.issues)


def test_zip_rejects_case_insensitive_duplicate_members(tmp_path: Path) -> None:
    zp = tmp_path / 'case.zip'
    with zipfile.ZipFile(zp, 'w') as zf:
        zf.writestr('pkg/README.md', b'a')
        zf.writestr('pkg/readme.md', b'b')
    report = audit_release(zp, run_cli_matrix=False)
    assert any(issue.category.startswith('ARCHIVE014') for issue in report.issues)


def test_markdown_rejects_percent_encoded_traversal(tmp_path: Path) -> None:
    (tmp_path / 'README.md').write_text('[x](docs/%2e%2e/secret.md)\n', encoding='utf-8')
    (tmp_path / 'docs').mkdir()
    report = audit_file_integrity(tmp_path)
    assert any(issue.category.startswith('LINK001') for issue in report.issues)
