"""
GitPulse - Scanner Engine
Combines Shannon entropy calculations and regex heuristic rules to detect hardcoded secrets
in source files, git diffs, and arbitrary text snippets.
"""

import re
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict, Tuple

from .entropy import calculate_shannon_entropy, analyze_token_entropy, get_entropy_level
from .patterns import get_rules, derive_env_var_name, SecretRule


@dataclass
class SecretFinding:
    rule_id: str
    rule_name: str
    secret_value: str
    masked_value: str
    line_number: int
    line_content: str
    file_path: str
    entropy: float
    threshold: float
    entropy_level: str
    entropy_color: str
    suggested_env_var: str
    start_col: int
    end_col: int
    is_diff: bool = False

    def to_dict(self) -> Dict:
        return asdict(self)


def mask_secret(secret: str, unmasked_prefix: int = 4, unmasked_suffix: int = 4) -> str:
    """
    Safely masks sensitive secret strings for display.
    Example: 'AKIA1234567890EXAMPLE' -> 'AKIA*************MPLE'
    """
    length = len(secret)
    if length <= 6:
        return "*" * length
    if length <= 10:
        return secret[:2] + "*" * (length - 4) + secret[-2:]
        
    p = min(unmasked_prefix, max(1, length // 4))
    s = min(unmasked_suffix, max(1, length // 4))
    return secret[:p] + "*" * (length - p - s) + secret[-s:]


class SecretScanner:
    def __init__(self, entropy_threshold_modifier: float = 0.0):
        self.rules = get_rules()
        self.entropy_modifier = entropy_threshold_modifier

    def scan_line(self, line: str, line_number: int, file_path: str = "snippet.py", is_diff: bool = False) -> List[SecretFinding]:
        """
        Scans a single line of text for hardcoded secrets.
        """
        findings: List[SecretFinding] = []
        found_spans = set()

        # Phase 1: Rule-based signature matching
        for rule in self.rules:
            for match in rule.regex.finditer(line):
                val = match.group(rule.capture_group) if rule.capture_group <= len(match.groups()) else match.group(0)
                span = match.span(rule.capture_group) if rule.capture_group <= len(match.groups()) else match.span(0)

                if not val or span in found_spans:
                    continue

                entropy = calculate_shannon_entropy(val)
                threshold = rule.min_entropy + self.entropy_modifier

                # If rule requires high entropy verification, check threshold
                if rule.requires_entropy and entropy < threshold:
                    continue

                level_name, color = get_entropy_level(entropy)
                suggested_env = derive_env_var_name(line, default_name=rule.recommended_env)

                finding = SecretFinding(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    secret_value=val,
                    masked_value=mask_secret(val),
                    line_number=line_number,
                    line_content=line.strip(),
                    file_path=file_path,
                    entropy=entropy,
                    threshold=threshold,
                    entropy_level=level_name,
                    entropy_color=color,
                    suggested_env_var=suggested_env,
                    start_col=span[0],
                    end_col=span[1],
                    is_diff=is_diff
                )
                findings.append(finding)
                found_spans.add(span)

        # Phase 2: High-entropy string literal detection (unsupervised fallback for arbitrary tokens in quotes)
        # Matches literals like "4f9a8b1c0e3d2f5a6b7c8d9e0f1a2b3c" or 'dGhpc2lzYXNhbXBsZXRva2VuMTIzNDU2Nzg='
        quoted_strings = re.finditer(r"['\"]([a-zA-Z0-9_\-\.\/+=]{20,})['\"]", line)
        for qm in quoted_strings:
            candidate = qm.group(1)
            span = qm.span(1)

            # Skip if already detected by rules
            if any(s[0] <= span[0] and s[1] >= span[1] for s in found_spans):
                continue

            analysis = analyze_token_entropy(candidate, min_length=20)
            if analysis["is_suspicious"]:
                suggested_env = derive_env_var_name(line, default_name="DETECTED_SECRET_TOKEN")
                finding = SecretFinding(
                    rule_id="HIGH_ENTROPY_LITERAL",
                    rule_name=f"High-Entropy String ({analysis['charset'].upper()})",
                    secret_value=candidate,
                    masked_value=mask_secret(candidate),
                    line_number=line_number,
                    line_content=line.strip(),
                    file_path=file_path,
                    entropy=analysis["entropy"],
                    threshold=analysis["threshold"],
                    entropy_level=analysis["level"],
                    entropy_color=analysis["color"],
                    suggested_env_var=suggested_env,
                    start_col=span[0],
                    end_col=span[1],
                    is_diff=is_diff
                )
                findings.append(finding)
                found_spans.add(span)

        return findings

    def scan_content(self, content: str, file_path: str = "snippet.py") -> List[SecretFinding]:
        """
        Scans complete text/file content line by line.
        """
        findings: List[SecretFinding] = []
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            line_findings = self.scan_line(line, line_number=idx, file_path=file_path, is_diff=False)
            findings.extend(line_findings)
        return findings

    def scan_git_diff(self, diff_text: str) -> List[SecretFinding]:
        """
        Scans a unified git diff, targeting lines being introduced/added ('+').
        Accurately reconstructs target line numbers from diff hunk headers '@@ -x,y +start,count @@'.
        """
        findings: List[SecretFinding] = []
        current_file = "unknown"
        current_line_num = 0
        in_hunk = False

        for raw_line in diff_text.splitlines():
            # Check for file header: +++ b/path/to/file.py
            if raw_line.startswith("+++ b/"):
                current_file = raw_line[6:].strip()
                continue
            elif raw_line.startswith("+++ "):
                current_file = raw_line[4:].strip()
                continue

            # Check for hunk header: @@ -a,b +start,length @@
            hunk_match = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", raw_line)
            if hunk_match:
                current_line_num = int(hunk_match.group(1))
                in_hunk = True
                continue

            if in_hunk:
                if raw_line.startswith("+") and not raw_line.startswith("+++"):
                    # This is an added line
                    added_content = raw_line[1:]  # strip leading '+'
                    line_findings = self.scan_line(
                        added_content,
                        line_number=current_line_num,
                        file_path=current_file,
                        is_diff=True
                    )
                    findings.extend(line_findings)
                    current_line_num += 1
                elif raw_line.startswith("-") and not raw_line.startswith("---"):
                    # Deleted line, do not increment new file line counter
                    pass
                else:
                    # Unchanged context line
                    current_line_num += 1

        return findings
