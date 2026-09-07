"""
GitPulse - Auto-Remediator Engine
Replaces hardcoded secrets with environment variable lookups and generates
unified .patch files and .env.example templates.
"""

import difflib
import os
import re
from typing import List, Dict, Tuple, Optional
from .scanner import SecretFinding


def get_replacement_syntax(env_var_name: str, file_path: str = "script.py", target_language: Optional[str] = None) -> str:
    """
    Returns the idiomatic environment variable retrieval syntax for the target language.
    """
    ext = os.path.splitext(file_path)[1].lower()
    lang = target_language.lower() if target_language else ""

    if lang in ["js", "javascript", "ts", "typescript"] or ext in [".js", ".jsx", ".ts", ".tsx", ".mjs"]:
        return f"process.env.{env_var_name}"
    elif lang in ["sh", "bash", "shell"] or ext in [".sh", ".bash", ".zsh"]:
        return f"${{{env_var_name}}}"
    elif lang in ["go", "golang"] or ext in [".go"]:
        return f'os.Getenv("{env_var_name}")'
    elif lang in ["ruby"] or ext in [".rb"]:
        return f'ENV["{env_var_name}"]'
    elif lang in ["php"] or ext in [".php"]:
        return f"getenv('{env_var_name}')"
    else:
        # Default Python
        return f'os.getenv("{env_var_name}")'


def remediate_line(line: str, finding: SecretFinding, custom_env_var: Optional[str] = None, target_language: Optional[str] = None) -> str:
    """
    Replaces the raw secret literal with the appropriate environment variable call,
    cleaning up wrapping quotes if present in an assignment.
    """
    secret = finding.secret_value
    env_var = custom_env_var or finding.suggested_env_var
    replacement = get_replacement_syntax(env_var, file_path=finding.file_path, target_language=target_language)

    # Check if secret was wrapped in quotes (e.g., "secret" or 'secret')
    # If so, replace quotes + secret with replacement expression
    pattern_double = f'"{secret}"'
    pattern_single = f"'{secret}'"

    if pattern_double in line:
        return line.replace(pattern_double, replacement, 1)
    elif pattern_single in line:
        return line.replace(pattern_single, replacement, 1)
    else:
        return line.replace(secret, replacement, 1)


class SecretRemediator:
    def __init__(self, target_language: Optional[str] = None):
        self.target_language = target_language

    def remediate_content(
        self,
        content: str,
        findings: List[SecretFinding],
        custom_env_vars: Optional[Dict[str, str]] = None,
        file_path: str = "vulnerable_code.py"
    ) -> Tuple[str, str, str]:
        """
        Takes original source text and findings, performs replacements, and returns:
        (sanitized_content, patch_unified_diff, env_example_content)
        """
        custom_env_vars = custom_env_vars or {}
        lines = content.splitlines(keepends=True)
        # Group findings by 1-based line number
        findings_by_line: Dict[int, List[SecretFinding]] = {}
        for f in findings:
            findings_by_line.setdefault(f.line_number, []).append(f)

        remediated_lines = []
        needed_env_vars = {}

        # Scan if Python import os is required
        needs_os_import = False
        ext = os.path.splitext(file_path)[1].lower()
        is_python = (self.target_language and "py" in self.target_language.lower()) or ext == ".py"

        for idx, line in enumerate(lines, start=1):
            current_line = line
            if idx in findings_by_line:
                for finding in findings_by_line[idx]:
                    env_name = custom_env_vars.get(finding.secret_value, finding.suggested_env_var)
                    needed_env_vars[env_name] = finding.rule_name
                    current_line = remediate_line(
                        current_line,
                        finding,
                        custom_env_var=env_name,
                        target_language=self.target_language
                    )
                    if is_python:
                        needs_os_import = True
            remediated_lines.append(current_line)

        # Prepend 'import os' for Python if not already present
        if is_python and needs_os_import:
            has_import_os = any(re.match(r"^\s*import\s+os\b", l) for l in remediated_lines)
            if not has_import_os:
                remediated_lines.insert(0, "import os\n")

        sanitized_content = "".join(remediated_lines)

        # Generate Unified Diff (.patch)
        orig_split = content.splitlines(keepends=True)
        rem_split = sanitized_content.splitlines(keepends=True)
        
        diff_lines = list(difflib.unified_diff(
            orig_split,
            rem_split,
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
            lineterm="\n"
        ))
        patch_text = "".join(diff_lines)

        # Generate .env.example
        env_lines = [
            "# ========================================================",
            "# GitPulse Auto-Remediation: Environment Variables",
            "# Populate these keys locally or in your CI/CD Secret Store",
            "# ========================================================\n"
        ]
        for env_key, rule_desc in sorted(needed_env_vars.items()):
            placeholder = env_key.lower() + "_here"
            env_lines.append(f"# {rule_desc}\n{env_key}=\"your_{placeholder}\"\n")
            
        env_example = "\n".join(env_lines)

        return sanitized_content, patch_text, env_example

    def generate_patch_file_content(self, original_text: str, remediated_text: str, filename: str = "code.py") -> str:
        """
        Creates standard git patch text from original and remediated strings.
        """
        orig_split = original_text.splitlines(keepends=True)
        rem_split = remediated_text.splitlines(keepends=True)
        diff_generator = difflib.unified_diff(
            orig_split,
            rem_split,
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
            lineterm="\n"
        )
        return "".join(diff_generator)
