import os
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from quantumguard.scanner import RuleSet  # noqa: E402


@pytest.fixture(scope="session")
def ruleset():
    return RuleSet.load()


class GitRepo:
    """Tiny helper that builds a Git repository with controlled timestamps."""

    def __init__(self, path: Path):
        self.path = path
        self.path.mkdir(parents=True, exist_ok=True)
        self.git("init", "-q", "-b", "main")

    def git(self, *args, date=None):
        env = dict(os.environ, GIT_AUTHOR_NAME="Test", GIT_AUTHOR_EMAIL="test@example.invalid",
                   GIT_COMMITTER_NAME="Test", GIT_COMMITTER_EMAIL="test@example.invalid")
        if date:
            env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = date
        result = subprocess.run(["git", "-c", "commit.gpgsign=false", "-C", str(self.path), *args],
                                capture_output=True, text=True, env=env, check=True)
        return result.stdout.strip()

    def write(self, rel, content):
        target = self.path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def delete(self, rel):
        (self.path / rel).unlink()

    def commit(self, message, date):
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message, date=date)
        return self.git("rev-parse", "HEAD")


@pytest.fixture
def make_repo(tmp_path):
    def _make(name="repo"):
        return GitRepo(tmp_path / name)
    return _make
