import unittest
from gitpulse.scanner import SecretScanner
from gitpulse.remediator import SecretRemediator

class TestRemediator(unittest.TestCase):
    def setUp(self):
        self.scanner = SecretScanner()
        self.remediator = SecretRemediator()

    def test_remediation_replaces_secret_with_os_getenv(self):
        code = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\nprint(AWS_KEY)\n'
        findings = self.scanner.scan_content(code, file_path="sample.py")
        self.assertEqual(len(findings), 1)

        sanitized, patch, env_ex = self.remediator.remediate_content(code, findings, file_path="sample.py")
        
        # Should replace raw string and strip surrounding quotes
        self.assertIn('AWS_KEY = os.getenv("AWS_KEY")', sanitized)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", sanitized)
        # Should include import os if python
        self.assertIn("import os", sanitized)
        # Should generate unified patch
        self.assertIn("--- a/sample.py", patch)
        self.assertIn("+++ b/sample.py", patch)
        # Should generate env.example
        self.assertIn('AWS_KEY="your_aws_key_here"', env_ex)

    def test_remediation_js_process_env(self):
        js_remediator = SecretRemediator(target_language="javascript")
        code = 'const stripeKey = "sk_live_51Abcdefghijklmnopqrstuvw";\n'
        findings = self.scanner.scan_content(code, file_path="config.js")
        self.assertGreaterEqual(len(findings), 1)

        sanitized, patch, env_ex = js_remediator.remediate_content(code, findings, file_path="config.js")
        self.assertIn("process.env.STRIPE_KEY", sanitized)
        self.assertNotIn("sk_live_51Abcdefghijklmnopqrstuvw", sanitized)

if __name__ == "__main__":
    unittest.main()
