"""Builds the reproducible SYNTHETIC demo repository from demo/templates/plan.json."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from .config import PROJECT_ROOT, QGError

TEMPLATES = PROJECT_ROOT / "demo" / "templates"
MARKER = ".quantumguard-demo"


def _git(repo: Path, *args: str, date: str | None = None) -> str:
    env = dict(os.environ, GIT_AUTHOR_NAME="QuantumGuard Demo", GIT_AUTHOR_EMAIL="demo@example.invalid",
               GIT_COMMITTER_NAME="QuantumGuard Demo", GIT_COMMITTER_EMAIL="demo@example.invalid",
               GIT_TERMINAL_PROMPT="0")
    if date:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = date
    proc = subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
                           "-C", str(repo), *args], capture_output=True, text=True, env=env, timeout=60)
    if proc.returncode != 0:
        raise QGError(f"git {args[0]} failed while building demo: {proc.stderr.strip()}")
    return proc.stdout.strip()


def load_plan() -> dict:
    return json.loads((TEMPLATES / "plan.json").read_text(encoding="utf-8"))


def build_demo_repo(target, force: bool = False) -> dict:
    target = Path(target).expanduser().resolve()
    if target.exists() and any(target.iterdir()):
        if not force:
            raise QGError(f"{target} is not empty. Use force=True to rebuild a previous demo repository.")
        if not (target / MARKER).exists():
            raise QGError(f"Refusing to delete {target}: it was not created by the QuantumGuard demo builder.")
        shutil.rmtree(target)
    target.mkdir(parents=True, exist_ok=True)
    plan = load_plan()
    _git(target, "init", "-q", "-b", "main")
    (target / ".git" / "info").mkdir(parents=True, exist_ok=True)
    (target / ".git" / "info" / "exclude").write_text(MARKER + "\n")
    (target / MARKER).write_text("Created by QuantumGuard demo builder. Safe to delete.\n")

    branches = ["main"]
    for step in plan["commits"]:
        branch = step["branch"]
        if branch != "main":
            _git(target, "checkout", "-q", "-b", branch, step.get("from", "main"))
            branches.append(branch)
        for rel, template in step.get("write", {}).items():
            dest = target / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text("" if template is None else (TEMPLATES / template).read_text(encoding="utf-8"),
                            encoding="utf-8")
        for rel in step.get("delete", []):
            (target / rel).unlink()
        _git(target, "add", "-A")
        _git(target, "commit", "-q", "-m", step["message"], date=step["date"])
        if branch != "main":
            _git(target, "checkout", "-q", "main")
    return {"path": str(target), "branches": branches, "expected_ci": plan.get("expected_ci", {})}
