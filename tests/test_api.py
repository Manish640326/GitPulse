import unittest
from api.index import scan_code, remediate_code, ScanRequest, RemediateRequest, health, get_presets

class TestVercelAPI(unittest.TestCase):
    def test_health(self):
        res = health()
        self.assertEqual(res["status"], "ok")

    def test_presets(self):
        presets = get_presets()
        self.assertIn("vulnerable_python", presets)

    def test_scan_api(self):
        req = ScanRequest(content='AWS_KEY = "AKIA1234567890ABCDEF"\n', filename="test.py")
        res = scan_code(req)
        self.assertEqual(res["total_secrets"], 1)
        self.assertEqual(res["findings"][0]["rule_id"], "AWS_ACCESS_KEY")

    def test_remediate_api(self):
        req = RemediateRequest(content='AWS_KEY = "AKIA1234567890ABCDEF"\n', filename="test.py")
        res = remediate_code(req)
        self.assertIn('AWS_KEY = os.getenv("AWS_KEY")', res["sanitized_code"])
        self.assertIn("--- a/test.py", res["patch_text"])

if __name__ == "__main__":
    unittest.main()
