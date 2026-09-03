"""
Family 5 — Distribution regression.

Marked `slow` because it builds and installs a real wheel —
tens of seconds, compared to milliseconds for the rest of the
suite. Uses pytest markers exclusively; there is no --run-slow
CLI flag and no conftest.py mechanism involved.

Fast suite (excludes this file):
    pytest -m "not slow"

Distribution suite (this file only):
    pytest -m slow

Direct execution:
    pytest tests/distribution/test_distribution_regression.py -m slow

Requires the marker to be registered in pyproject.toml's
[tool.pytest.ini_options]:

    markers = [
        "slow: builds a real wheel — run explicitly, not in the default fast loop",
    ]

REPO-LEVEL POLICY STILL OPEN, not resolved by this file alone:
existing CI and release workflows currently invoke the whole
tree directly (e.g. `python -m pytest tests/`), which means once
this file exists, those jobs will build a wheel on every run
unless their invocations are explicitly updated to `-m "not slow"`
for fast jobs and `-m slow` for a dedicated distribution/release
job. Same for the README's documented `pytest tests/ -v` command.
This is real, unresolved repository configuration work — flagged
here rather than silently assumed handled.
"""

import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.slow


_REQUIRED_AUTHORITY_MODULES = {
    "authority/local_provider.py",
    "authority/models.py",
    "authority/organization_loader.py",
    "authority/provider.py",
}


@pytest.fixture(scope="module")
def built_wheel_path(tmp_path_factory):
    """
    Builds a real wheel once per test module run, from an
    ISOLATED TEMPORARY COPY of the source tree — never the live
    repo in place.

    An earlier version of this fixture deleted the repo root's
    build/ and *.egg-info/ directories directly, to work around a
    real problem: `python -m build` stages intermediate output in
    the repo root regardless of --outdir, and setuptools does not
    always re-copy every file on a rebuild — a stale staged copy
    from a PREVIOUS build (e.g. before a filename fix) can
    silently persist and get repackaged, producing a false
    "regression." That diagnosis was correct, but deleting
    packaging metadata from the live checkout as a test side
    effect is itself a problem: in an editable install, *.egg-info
    can be part of what the active environment relies on, and a
    test should not mutate shared developer state to make itself
    pass.

    This version instead copies the source tree into a disposable
    temp workspace (excluding build/, dist/, *.egg-info, venvs,
    caches, and .git) and builds THERE. The build is now hermetic
    by construction — there is no repo-root staging state to go
    stale in the first place, so this class of false-negative
    cannot recur, and the live repo is never touched.
    """
    import shutil

    repo_root = Path(__file__).parent.parent.parent
    workspace = tmp_path_factory.mktemp("build-workspace")

    _EXCLUDE_DIRS = {
        "build", "dist", ".git", "__pycache__",
        "owv-venv-windows", "owv-venv-wsl",
    }

    def _ignore(directory, names):
        ignored = set()
        for name in names:
            if name in _EXCLUDE_DIRS or name.endswith(".egg-info"):
                ignored.add(name)
        return ignored

    shutil.copytree(repo_root, workspace / "src", ignore=_ignore)
    source_copy = workspace / "src"

    dist_dir = tmp_path_factory.mktemp("dist")

    result = subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(dist_dir)],
        cwd=str(source_copy),
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, (
        f"wheel build failed:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )

    wheels = list(dist_dir.glob("*.whl"))
    assert len(wheels) == 1, f"expected exactly one wheel, found {wheels}"
    return wheels[0]


class TestWheelContainsAuthorityPackage:
    def test_all_authority_modules_present_in_wheel(self, built_wheel_path):
        with zipfile.ZipFile(built_wheel_path) as z:
            names = set(z.namelist())

        missing = _REQUIRED_AUTHORITY_MODULES - names
        assert not missing, (
            f"authority/ modules missing from built wheel: {missing}. "
            f"This means [tool.setuptools.packages.find].include in "
            f"pyproject.toml does not correctly include 'authority*', "
            f"or has regressed since it was last confirmed working."
        )

    def test_no_malformed_translator_init_filename(self, built_wheel_path):
        """
        Regression test for the stray-space filename defect
        confirmed present in an earlier build
        ('context/translators/ __init__.py') and since fixed —
        this test exists specifically so that fix cannot silently
        regress.
        """
        with zipfile.ZipFile(built_wheel_path) as z:
            names = z.namelist()

        malformed = [n for n in names if "translators/ __init__" in n]
        assert not malformed, f"malformed filename regressed: {malformed}"

        correct = "context/translators/__init__.py"
        assert correct in names, f"{correct} missing from wheel entirely"


class TestWheelInstallsAndImportsCleanly:
    def test_clean_install_imports_authority_package(self, built_wheel_path, tmp_path):
        """
        The real test a PyPI user's experience maps to: a
        NON-editable install of the actual built artifact,
        confirming authority/ imports correctly from the
        installed package location, not from a source checkout
        on PYTHONPATH.
        """
        venv_dir = tmp_path / "install-test-venv"
        subprocess.run(
            [sys.executable, "-m", "venv", str(venv_dir)], check=True, timeout=60
        )

        if sys.platform == "win32":
            venv_python = venv_dir / "Scripts" / "python.exe"
        else:
            venv_python = venv_dir / "bin" / "python"

        install_result = subprocess.run(
            [str(venv_python), "-m", "pip", "install", str(built_wheel_path)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert install_result.returncode == 0, install_result.stdout + install_result.stderr

        import_result = subprocess.run(
            [
                str(venv_python),
                "-c",
                "from authority.local_provider import LocalOrganizationAuthorityProvider; "
                "print('OK')",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert import_result.returncode == 0, (
            f"authority package failed to import from a clean, "
            f"non-editable wheel install:\n{import_result.stdout}\n"
            f"{import_result.stderr}"
        )
        assert "OK" in import_result.stdout


class TestPackageMetadataDependencies:
    def test_filelock_and_email_validator_declared(self, built_wheel_path):
        with zipfile.ZipFile(built_wheel_path) as z:
            metadata_files = [n for n in z.namelist() if n.endswith("METADATA")]
            assert len(metadata_files) == 1
            metadata_content = z.read(metadata_files[0]).decode("utf-8")

        assert "filelock" in metadata_content.lower(), (
            "filelock not found in wheel METADATA — pyproject.toml "
            "dependency declaration may have regressed"
        )
        assert "email-validator" in metadata_content.lower(), (
            "email-validator not found in wheel METADATA — pyproject.toml "
            "dependency declaration may have regressed"
        )