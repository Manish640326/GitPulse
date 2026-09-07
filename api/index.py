"""
GitPulse - Vercel Serverless Function (FastAPI)
Provides RESTful API for secret scanning, Shannon entropy analysis, and auto-remediation.
"""

import os
import sys
from typing import Dict, List, Optional
from pydantic import BaseModel
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

# Ensure parent directory is in Python path for gitpulse imports
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from gitpulse.scanner import SecretScanner
from gitpulse.remediator import SecretRemediator
from gitpulse.entropy import calculate_shannon_entropy

app = FastAPI(
    title="GitPulse API",
    description="DevSecOps Pre-Commit Secret Interceptor & Auto-Remediator API",
    version="1.0.0"
)

# Enable CORS for Vercel deployments
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    content: str
    filename: Optional[str] = "snippet.py"
    is_diff: Optional[bool] = False
    entropy_modifier: Optional[float] = 0.0

class RemediateRequest(BaseModel):
    content: str
    filename: Optional[str] = "snippet.py"
    is_diff: Optional[bool] = False
    custom_env_vars: Optional[Dict[str, str]] = None
    target_lang: Optional[str] = None

PRESET_SAMPLES = {
    "vulnerable_python": {
        "title": "Python API Client (AWS, OpenAI, DB Password)",
        "filename": "service.py",
        "lang": "python",
        "is_diff": False,
        "content": '''import requests

# Hardcoded Cloud Credentials
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# OpenAI API Key
openai_api_key = "sk-proj-abc1234567890def1234567890ghi1234567890"

# Database Credential
db_password = "d41d8cd98f00b204e9800998ecf8427e"

def query_openai(prompt):
    headers = {"Authorization": f"Bearer {openai_api_key}"}
    return requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json={"prompt": prompt})
'''
    },
    "cloud_diff": {
        "title": "Git Diff Commit (AWS Key, GitHub PAT, Stripe Secret)",
        "filename": "commit.diff",
        "lang": "python",
        "is_diff": True,
        "content": '''diff --git a/src/cloud_client.py b/src/cloud_client.py
index e69de29..b1b2c3d 100644
--- a/src/cloud_client.py
+++ b/src/cloud_client.py
@@ -10,6 +10,12 @@ def initialize_cloud_sync():
     print("Connecting to storage bucket...")
+    # Leaked direct credentials
+    aws_key = "AKIA1234567890ABCDEF"
+    github_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
+    stripe_secret = "sk_live_51Abcdefghijklmnopqrstuvw"
+
     session = create_session(aws_key)
     return session
'''
    },
    "js_config": {
        "title": "Node.js Config (Stripe Key & Slack Bot Token)",
        "filename": "config.js",
        "lang": "javascript",
        "is_diff": False,
        "content": '''// Node.js Configuration Service
const config = {
  appName: "PaymentGatewayService",
  port: 8080,
  stripeSecretKey: "sk_live_998877665544332211aabbcc",
  slackWebhookToken: "xoxb-123456789012-123456789012-abcdef1234567890abcdef12"
};

module.exports = config;
'''
    }
}

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "GitPulse Secret Interceptor", "version": "1.0.0"}

@app.get("/api/presets")
def get_presets():
    return PRESET_SAMPLES

@app.post("/api/scan")
def scan_code(req: ScanRequest):
    try:
        scanner = SecretScanner(entropy_threshold_modifier=req.entropy_modifier)
        if req.is_diff or req.filename.endswith((".diff", ".patch")):
            findings = scanner.scan_git_diff(req.content)
        else:
            findings = scanner.scan_content(req.content, file_path=req.filename)

        findings_data = [f.to_dict() for f in findings]
        max_entropy = max([f.entropy for f in findings], default=0.0)

        return {
            "total_secrets": len(findings),
            "max_entropy": max_entropy,
            "risk_state": "High Risk" if findings else "Clean",
            "findings": findings_data
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/remediate")
def remediate_code(req: RemediateRequest):
    try:
        scanner = SecretScanner()
        if req.is_diff or req.filename.endswith((".diff", ".patch")):
            findings = scanner.scan_git_diff(req.content)
        else:
            findings = scanner.scan_content(req.content, file_path=req.filename)

        remediator = SecretRemediator(target_language=req.target_lang)

        if not req.is_diff:
            sanitized_code, patch_text, env_example = remediator.remediate_content(
                req.content,
                findings,
                custom_env_vars=req.custom_env_vars,
                file_path=req.filename
            )
        else:
            # Handle diff replacement
            custom_map = req.custom_env_vars or {}
            remediated_diff = req.content
            needed_envs = {}
            for f in findings:
                env_name = custom_map.get(f.secret_value, f.suggested_env_var)
                syntax = f'os.getenv("{env_name}")'
                remediated_diff = remediated_diff.replace(f'"{f.secret_value}"', syntax)
                remediated_diff = remediated_diff.replace(f"'{f.secret_value}'", syntax)
                remediated_diff = remediated_diff.replace(f.secret_value, syntax)
                needed_envs[env_name] = f.rule_name

            sanitized_code = remediated_diff
            patch_text = remediated_diff
            env_lines = ["# GitPulse Generated Environment Template\n"]
            for k, v in needed_envs.items():
                env_lines.append(f"# {v}\n{k}=\"your_{k.lower()}_here\"\n")
            env_example = "\n".join(env_lines)

        return {
            "sanitized_code": sanitized_code,
            "patch_text": patch_text,
            "env_example": env_example,
            "remediated_count": len(findings)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
