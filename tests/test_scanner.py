import unittest
from gitpulse.scanner import SecretScanner, mask_secret

class TestScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = SecretScanner()

    def test_mask_secret(self):
        self.assertEqual(mask_secret("AKIAIOSFODNN7EXAMPLE"), "AKIA************MPLE")
        self.assertEqual(mask_secret("short"), "*****")

    def test_detect_aws_key(self):
        line = 'aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"'
        findings = self.scanner.scan_line(line, line_number=1, file_path="config.py")
        self.assertTrue(any(f.rule_id == "AWS_ACCESS_KEY" for f in findings))
        f = next(f for f in findings if f.rule_id == "AWS_ACCESS_KEY")
        self.assertEqual(f.secret_value, "AKIAIOSFODNN7EXAMPLE")
        self.assertEqual(f.suggested_env_var, "AWS_ACCESS_KEY_ID")

    def test_detect_openai_key(self):
        line = 'client = OpenAI(api_key="sk-proj-1234567890abcdef1234567890abcdef1234567890")'
        findings = self.scanner.scan_line(line, line_number=5, file_path="app.py")
        self.assertTrue(any(f.rule_id == "OPENAI_API_KEY" for f in findings))

    def test_detect_github_token(self):
        line = 'github_pat = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"'
        findings = self.scanner.scan_line(line, line_number=2, file_path="ci.py")
        self.assertTrue(any(f.rule_id == "GITHUB_PAT" for f in findings))

    def test_scan_git_diff(self):
        diff = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,3 +1,4 @@
 import os
+stripe_token = "sk_live_51Abcdefghijklmnopqrstuvw"
 def run():
"""
        findings = self.scanner.scan_git_diff(diff)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "STRIPE_KEY")
        self.assertEqual(findings[0].line_number, 2)
        self.assertEqual(findings[0].file_path, "app.py")

    def test_ignore_clean_code(self):
        clean_code = """
def calculate_sum(a, b):
    # This is a normal function
    return a + b
"""
        findings = self.scanner.scan_content(clean_code, file_path="clean.py")
        self.assertEqual(len(findings), 0)

if __name__ == "__main__":
    unittest.main()
