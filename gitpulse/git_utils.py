"""
GitPulse - Git Utilities
Provides helper methods for interacting with local Git repositories,
extracting staged/unstaged diffs, and applying remediation patches.
"""

import subprocess
import shutil
from typing import Tuple, Optional


def is_git_installed() -> bool:
    """Checks if git binary is present in system PATH."""
    return shutil.which("git") is not None


def is_git_repo(repo_path: str = ".") -> bool:
    """Checks if specified directory is inside a Git repository."""
    if not is_git_installed():
        return False
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=False
        )
        return res.returncode == 0 and "true" in res.stdout.strip()
    except Exception:
        return False


def get_staged_diff(repo_path: str = ".") -> Tuple[bool, str]:
    """
    Returns (success, diff_text) for staged changes (git diff --cached).
    Ideal for pre-commit checks!
    """
    try:
        res = subprocess.run(
            ["git", "diff", "--cached", "-U3"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=False
        )
        if res.returncode == 0:
            return True, res.stdout
        return False, res.stderr
    except Exception as e:
        return False, str(e)


def get_unstaged_diff(repo_path: str = ".") -> Tuple[bool, str]:
    """Returns (success, diff_text) for unstaged working directory changes (git diff)."""
    try:
        res = subprocess.run(
            ["git", "diff", "-U3"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=False
        )
        if res.returncode == 0:
            return True, res.stdout
        return False, res.stderr
    except Exception as e:
        return False, str(e)


def apply_patch(patch_content: str, repo_path: str = ".") -> Tuple[bool, str]:
    """Applies a unified patch to the git working tree."""
    try:
        process = subprocess.Popen(
            ["git", "apply", "--whitespace=fix", "-"],
            cwd=repo_path,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate(input=patch_content)
        if process.returncode == 0:
            return True, "Patch applied successfully via git apply."
        return False, stderr or stdout
    except Exception as e:
        return False, str(e)
