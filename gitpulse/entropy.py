"""
GitPulse - Shannon Entropy Engine
Calculates information density and entropy for string tokens to detect high-randomness secrets.
"""

import math
from collections import Counter
from typing import Dict, Tuple


HEX_CHARS = set("0123456789abcdefABCDEF")
BASE64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")
ALPHANUM_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")


def calculate_shannon_entropy(text: str) -> float:
    """
    Calculate the Shannon entropy of a string token.
    H(X) = -sum(P(x_i) * log2(P(x_i)))
    
    A higher score indicates greater randomness / information density.
    Standard English text: ~2.5 - 3.5
    Hexadecimal hashes/keys (MD5/SHA/Hex API keys): ~3.0 - 4.0 (max log2(16) = 4.0)
    Base64 encoded tokens / random API keys: ~4.3 - 6.0 (max log2(64) = 6.0)
    """
    if not text:
        return 0.0

    length = len(text)
    char_counts = Counter(text)
    
    entropy = 0.0
    for count in char_counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
        
    return round(entropy, 4)


def classify_charset(text: str) -> str:
    """
    Classifies the token's character set to select appropriate entropy thresholds.
    """
    text_set = set(text)
    if text_set.issubset(HEX_CHARS):
        return "hex"
    elif text_set.issubset(ALPHANUM_CHARS):
        return "alphanumeric"
    elif text_set.issubset(BASE64_CHARS):
        return "base64"
    else:
        return "mixed"


def get_default_threshold(charset: str) -> float:
    """
    Returns baseline Shannon entropy threshold for given character set.
    """
    thresholds = {
        "hex": 3.0,          # Theoretical max: 4.0 (16 chars)
        "alphanumeric": 3.8, # Theoretical max: ~5.95 (62 chars)
        "base64": 4.2,       # Theoretical max: 6.0 (64 chars)
        "mixed": 4.0
    }
    return thresholds.get(charset, 3.8)


def get_entropy_level(entropy: float) -> Tuple[str, str]:
    """
    Returns human-friendly risk level and color for a given entropy score.
    Returns: (level_name, color_hex)
    """
    if entropy >= 4.5:
        return "Critical Randomness", "#FF4B4B"
    elif entropy >= 3.8:
        return "High Randomness", "#FFA500"
    elif entropy >= 3.0:
        return "Moderate Randomness", "#3B82F6"
    else:
        return "Low Randomness", "#10B981"


def analyze_token_entropy(token: str, min_length: int = 16, custom_threshold: float = None) -> Dict:
    """
    Performs full entropy inspection on a single candidate token.
    """
    entropy = calculate_shannon_entropy(token)
    charset = classify_charset(token)
    threshold = custom_threshold if custom_threshold is not None else get_default_threshold(charset)
    
    level_name, color = get_entropy_level(entropy)
    
    # Calculate max theoretical entropy for this length and alphabet
    alphabet_size = len(set(token))
    max_theoretical = round(math.log2(alphabet_size), 4) if alphabet_size > 1 else 0.0
    
    is_suspicious = len(token) >= min_length and entropy >= threshold
    
    return {
        "token": token,
        "length": len(token),
        "entropy": entropy,
        "charset": charset,
        "threshold": threshold,
        "is_suspicious": is_suspicious,
        "level": level_name,
        "color": color,
        "max_theoretical": max_theoretical,
        "ratio_of_max": round((entropy / max_theoretical), 2) if max_theoretical > 0 else 0.0
    }
