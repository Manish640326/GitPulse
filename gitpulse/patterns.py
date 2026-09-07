"""
GitPulse - Known Secret Signatures and Heuristic Patterns
Curated regex patterns for high-risk cloud credentials, tokens, and generic secrets.
"""

import re
from typing import List, Dict, Optional


class SecretRule:
    def __init__(
        self,
        rule_id: str,
        name: str,
        pattern: str,
        description: str,
        recommended_env: str,
        min_entropy: float = 3.0,
        requires_entropy: bool = False,
        capture_group: int = 0
    ):
        self.rule_id = rule_id
        self.name = name
        self.pattern = pattern
        self.regex = re.compile(pattern)
        self.description = description
        self.recommended_env = recommended_env
        self.min_entropy = min_entropy
        self.requires_entropy = requires_entropy
        self.capture_group = capture_group


RULES: List[SecretRule] = [
    SecretRule(
        rule_id="AWS_ACCESS_KEY",
        name="AWS Access Key ID",
        pattern=r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})(?![A-Z0-9])",
        description="Amazon Web Services 20-character Access Key ID identifier.",
        recommended_env="AWS_ACCESS_KEY_ID",
        min_entropy=2.8,
        requires_entropy=False,
        capture_group=1
    ),
    SecretRule(
        rule_id="AWS_SECRET_KEY",
        name="AWS Secret Access Key",
        pattern=r"(?i)(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]",
        description="Amazon Web Services 40-character Secret Access Key.",
        recommended_env="AWS_SECRET_ACCESS_KEY",
        min_entropy=3.8,
        requires_entropy=True,
        capture_group=1
    ),
    SecretRule(
        rule_id="GITHUB_PAT",
        name="GitHub Personal Access Token",
        pattern=r"(?<![a-zA-Z0-9_])(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{60,90}|gho_[0-9a-zA-Z]{36})(?![a-zA-Z0-9_])",
        description="GitHub authentication token (classic or fine-grained).",
        recommended_env="GITHUB_TOKEN",
        min_entropy=3.6,
        requires_entropy=False,
        capture_group=1
    ),
    SecretRule(
        rule_id="OPENAI_API_KEY",
        name="OpenAI API Key",
        pattern=r"(?<![a-zA-Z0-9_])(sk-[a-zA-Z0-9_-]{32,}|sk-proj-[a-zA-Z0-9_-]{40,})(?![a-zA-Z0-9_])",
        description="OpenAI API key for ChatGPT / GPT models.",
        recommended_env="OPENAI_API_KEY",
        min_entropy=3.8,
        requires_entropy=False,
        capture_group=1
    ),
    SecretRule(
        rule_id="STRIPE_KEY",
        name="Stripe Secret Key",
        pattern=r"(?<![a-zA-Z0-9_])((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,34})(?![a-zA-Z0-9_])",
        description="Stripe payment gateway secret or restricted key.",
        recommended_env="STRIPE_SECRET_KEY",
        min_entropy=3.5,
        requires_entropy=False,
        capture_group=1
    ),
    SecretRule(
        rule_id="SLACK_TOKEN",
        name="Slack Bot/User Token",
        pattern=r"(?<![a-zA-Z0-9_])(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}|xox[baprs]-[0-9a-zA-Z]{24,48})(?![a-zA-Z0-9_])",
        description="Slack integration Bot or User OAuth Token.",
        recommended_env="SLACK_BOT_TOKEN",
        min_entropy=3.2,
        requires_entropy=False,
        capture_group=1
    ),
    SecretRule(
        rule_id="GOOGLE_API_KEY",
        name="Google Cloud / Maps API Key",
        pattern=r"(?<![a-zA-Z0-9_])(AIza[0-9A-Za-z\\-_]{35})(?![a-zA-Z0-9_])",
        description="Google Cloud Platform or Firebase API Key.",
        recommended_env="GOOGLE_API_KEY",
        min_entropy=3.5,
        requires_entropy=False,
        capture_group=1
    ),
    SecretRule(
        rule_id="JWT_TOKEN",
        name="JSON Web Token (JWT)",
        pattern=r"(?<![a-zA-Z0-9_])(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})(?![a-zA-Z0-9_])",
        description="Signed JSON Web Token (JWT) bearer credential.",
        recommended_env="JWT_AUTH_TOKEN",
        min_entropy=3.8,
        requires_entropy=False,
        capture_group=1
    ),
    SecretRule(
        rule_id="PRIVATE_KEY_BLOCK",
        name="Private Encryption Key",
        pattern=r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
        description="Asymmetric cryptographic private key block.",
        recommended_env="PRIVATE_KEY",
        min_entropy=2.0,
        requires_entropy=False,
        capture_group=0
    ),
    SecretRule(
        rule_id="GENERIC_API_KEY",
        name="Generic Hardcoded Secret Assignment",
        pattern=r"(?i)(?:api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token|client[_-]?secret|private[_-]?key|password|db_pass|database_password)\s*[:=]\s*['\"]([^'\"\s]{12,})['\"]",
        description="Variable or config assignment containing a high-entropy secret string.",
        recommended_env="APP_SECRET_KEY",
        min_entropy=3.6,
        requires_entropy=True,  # Generic assignments must cross entropy threshold to reduce false alarms
        capture_group=1
    ),
    SecretRule(
        rule_id="GENERIC_BEARER_TOKEN",
        name="Generic Bearer Authorization Token",
        pattern=r"(?i)Bearer\s+([a-zA-Z0-9_\-\.]{20,})",
        description="Authorization Bearer header with inline security token.",
        recommended_env="BEARER_TOKEN",
        min_entropy=3.7,
        requires_entropy=True,
        capture_group=1
    )
]


def get_rules() -> List[SecretRule]:
    """Returns list of active detection rules."""
    return RULES


def derive_env_var_name(variable_context: Optional[str], default_name: str = "SECRET_TOKEN") -> str:
    """
    Cleverly derives an UPPERCASE_SNAKE_CASE environment variable name from a code line.
    E.g., `client_secret = "..."` -> `CLIENT_SECRET`
          `TWILIO_ACCOUNT_SID = "..."` -> `TWILIO_ACCOUNT_SID`
    """
    if not variable_context:
        return default_name
        
    # Match LHS of assignment: var_name = "..."
    lhs_match = re.search(r"^\s*(?:const|let|var|val|public|private)?\s*([a-zA-Z0-9_]+)\s*[:=]", variable_context)
    if lhs_match:
        var_name = lhs_match.group(1).strip()
        # Convert camelCase to snake_case if necessary
        s1 = re.sub(r'(.)([A-Z][a-z]+)', r'\1_\2', var_name)
        s2 = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', s1)
        cleaned = re.sub(r'[^a-zA-Z0-9_]', '_', s2).upper()
        # Ensure it's not too trivial
        if len(cleaned) >= 3:
            return cleaned
            
    return default_name
