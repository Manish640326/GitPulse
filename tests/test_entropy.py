import unittest
from gitpulse.entropy import (
    calculate_shannon_entropy,
    classify_charset,
    get_default_threshold,
    analyze_token_entropy
)

class TestEntropy(unittest.TestCase):
    def test_empty_string(self):
        self.assertEqual(calculate_shannon_entropy(""), 0.0)

    def test_single_character_string(self):
        # Uniform string 'aaaa' has 0 entropy because probability of 'a' is 1.0 -> -1 * log2(1) = 0
        self.assertEqual(calculate_shannon_entropy("aaaaaaa"), 0.0)

    def test_binary_alternating_string(self):
        # 50% 'a', 50% 'b' -> -2 * (0.5 * log2(0.5)) = 1.0
        self.assertAlmostEqual(calculate_shannon_entropy("abababab"), 1.0, places=3)

    def test_high_randomness_token(self):
        # A 32-character hex key should have high entropy (close to ~3.5 - 4.0)
        hex_secret = "4f9a8b1c0e3d2f5a6b7c8d9e0f1a2b3c"
        entropy = calculate_shannon_entropy(hex_secret)
        self.assertGreater(entropy, 3.2)

    def test_charset_classification(self):
        self.assertEqual(classify_charset("deadbeef12345678"), "hex")
        self.assertEqual(classify_charset("abcXYZ123"), "alphanumeric")
        self.assertEqual(classify_charset("abcXYZ123+/="), "base64")
        self.assertEqual(classify_charset("abcXYZ!@#"), "mixed")

    def test_analyze_token_entropy(self):
        analysis = analyze_token_entropy("dGhpc2lzYXNhbXBsZXRva2VuMTIzNDU2Nzg=")
        self.assertIn("entropy", analysis)
        self.assertIn("charset", analysis)
        self.assertIn("is_suspicious", analysis)
        self.assertGreater(analysis["entropy"], 3.5)

if __name__ == "__main__":
    unittest.main()
