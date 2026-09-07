"""
GitPulse - Scanner Engine
Combines Shannon entropy calculations, regex heuristic rules, and context/variable analysis
to detect hardcoded secrets and explain why each secret was flagged.
"""

import re
from dataclasses import dataclass, asdict, field
from typing import List, Optional, Dict, Tuple

from .entropy import calculate_shannon_entropy, analyze_token_entropy, get_entropy_level
from .patterns import get_rules, derive_env_var_name, SecretRule


SENSITIVE_CONTEXT_KEYWORDS = [
    "key", "secret", "token", "password", "passwd", "pwd", "auth",
    "cred", "credential", "private", "access", "bearer", "session", "api"
]


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
    risk_score: int = 70
    risk_label: str = "HIGH"
    risk_badge: str = "🔴 HIGH"
    reasons: List[str] = field(default_factory=list)
    tri_factors: Dict[str, bool] = field(default_factory=lambda: {"pattern": True, "entropy": True, "context": True})
    diff_transformation: str = ""

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


def detect_context_sensitivity(line: str) -> Tuple[bool, Optional[str]]:
    """
    Analyzes whether the surrounding line has credential-like variable names or assignments.
    """
    lower_line = line.lower()
    for kw in SENSITIVE_CONTEXT_KEYWORDS:
        if re.search(rf"\b{kw}\b", lower_line):
            return True, kw
    return False, None


def compute_composite_risk(
    has_pattern: bool,
    pattern_name: str,
    entropy: float,
    threshold: float,
    has_context: bool,
    context_kw: Optional[str],
    line_content: str,
    suggested_env: str,
    secret_val: str
) -> Tuple[int, str, str, List[str], Dict[str, bool], str]:
    """
    Computes a multi-factor risk score (0-100), risk badge, and generates
    the "Why was this flagged?" explanatory checklist.
    """
    score = 0
    reasons = []

    # Factor 1: Signature / Pattern match (up to 40 pts)
    if has_pattern and "GENERIC" not in pattern_name.upper() and "HIGH_ENTROPY" not in pattern_name.upper():
        score += 40
        reasons.append(f"Matches known credential signature: {pattern_name}")
    elif has_pattern:
        score += 25
        reasons.append(f"Matches sensitive assignment pattern: {pattern_name}")

    # Factor 2: Shannon Entropy Analysis (up to 35 pts)
    if entropy >= 4.5:
        score += 35
        reasons.append(f"Critical Shannon entropy ({entropy:.3f} bits > {threshold:.2f} threshold) — indicates cryptographic randomness")
    elif entropy >= threshold:
        score += 25
        reasons.append(f"Elevated Shannon entropy ({entropy:.3f} bits > {threshold:.2f} threshold) — high character diversity")
    else:
        score += 10
        reasons.append(f"Moderate entropy ({entropy:.3f} bits)")

    # Factor 3: Variable & Assignment Context (up to 25 pts)
    if has_context:
        score += 25
        reasons.append(f"Credential-like assignment context detected (keyword: '{context_kw}')")
    else:
        reasons.append("Appears directly as inline string literal in source code")

    # Additional reasoning
    reasons.append(f"Suggested safe remediation: Move to environment variable '{suggested_env}'")

    # Classify Risk Tier
    if score >= 80:
        label = "CRITICAL"
        badge = "🔴 CRITICAL"
    elif score >= 60:
        label = "HIGH"
        badge = "🟠 HIGH"
    elif score >= 40:
        label = "MEDIUM"
        badge = "🟡 MEDIUM"
    else:
        label = "LOW"
        badge = "🟢 LOW"

    tri_factors = {
        "pattern": bool(has_pattern),
        "entropy": bool(entropy >= threshold),
        "context": bool(has_context)
    }

    # Format sample transformation
    rep_target = f'os.getenv("{suggested_env}")'
    clean_line = line_content
    replaced = False
    for quote in ['"', "'"]:
        pattern = f"{quote}{secret_val}{quote}"
        if pattern in clean_line:
            clean_line = clean_line.replace(pattern, rep_target, 1)
            replaced = True
            break
    if not replaced:
        clean_line = clean_line.replace(secret_val, rep_target, 1)

    diff_transformation = f"- {line_content}\n+ {clean_line}"

    return score, label, badge, reasons, tri_factors, diff_transformation


class SecretScanner:
    def __init__(self, entropy_threshold_modifier: float = 0.0):
        self.rules = get_rules()
        self.entropy_modifier = entropy_threshold_modifier

    def scan_line(self, line: str, line_number: int, file_path: str = "snippet.py", is_diff: bool = False) -> List[SecretFinding]:
        """
        Scans a single line of text for hardcoded secrets with multi-factor risk analysis.
        """
        findings: List[SecretFinding] = []
        found_spans = set()
        has_context, context_kw = detect_context_sensitivity(line)

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

                score, label, badge, reasons, tri_factors, transformation = compute_composite_risk(
                    has_pattern=True,
                    pattern_name=rule.name,
                    entropy=entropy,
                    threshold=threshold,
                    has_context=has_context,
                    context_kw=context_kw,
                    line_content=line.strip(),
                    suggested_env=suggested_env,
                    secret_val=val
                )

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
                    is_diff=is_diff,
                    risk_score=score,
                    risk_label=label,
                    risk_badge=badge,
                    reasons=reasons,
                    tri_factors=tri_factors,
                    diff_transformation=transformation
                )
                findings.append(finding)
                found_spans.add(span)

        # Phase 2: High-entropy string literal detection (unsupervised fallback for arbitrary tokens in quotes)
        quoted_strings = re.finditer(r"['\"]([a-zA-Z0-9_\-\.\/+=]{16,})['\"]", line)
        for qm in quoted_strings:
            candidate = qm.group(1)
            span = qm.span(1)

            # Skip if already detected by rules
            if any(s[0] <= span[0] and s[1] >= span[1] for s in found_spans):
                continue

            analysis = analyze_token_entropy(candidate, min_length=16)
            if analysis["is_suspicious"]:
                suggested_env = derive_env_var_name(line, default_name="DETECTED_SECRET_TOKEN")

                score, label, badge, reasons, tri_factors, transformation = compute_composite_risk(
                    has_pattern=False,
                    pattern_name=f"High-Entropy String ({analysis['charset'].upper()})",
                    entropy=analysis["entropy"],
                    threshold=analysis["threshold"],
                    has_context=has_context,
                    context_kw=context_kw,
                    line_content=line.strip(),
                    suggested_env=suggested_env,
                    secret_val=candidate
                )

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
                    is_diff=is_diff,
                    risk_score=score,
                    risk_label=label,
                    risk_badge=badge,
                    reasons=reasons,
                    tri_factors=tri_factors,
                    diff_transformation=transformation
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
                    # Added line in diff
                    added_content = raw_line[1:]
                    line_findings = self.scan_line(
                        added_content,
                        line_number=current_line_num,
                        file_path=current_file,
                        is_diff=True
                    )
                    findings.extend(line_findings)
                    current_line_num += 1
                elif raw_line.startswith("-") and not raw_line.startswith("---"):
                    pass
                else:
                    current_line_num += 1

        return findings
