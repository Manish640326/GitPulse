"""
GitPulse - Streamlit Dashboard
Git Pre-Commit Secret Interceptor & Auto-Remediator
"""

import os
import streamlit as st
import pandas as pd
from typing import List, Dict

from gitpulse.entropy import calculate_shannon_entropy, analyze_token_entropy, get_entropy_level
from gitpulse.patterns import get_rules
from gitpulse.scanner import SecretScanner, SecretFinding, mask_secret
from gitpulse.remediator import SecretRemediator
from gitpulse.git_utils import is_git_repo, get_staged_diff, apply_patch, is_git_installed

# Page Configuration
st.set_page_config(
    page_title="GitPulse — Stop Secrets Before They Reach Git",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.3rem;
        font-weight: 900;
        background: linear-gradient(90deg, #60A5FA 0%, #A78BFA 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1.05rem;
        color: #94A3B8;
        margin-bottom: 1rem;
    }
    .badge-pill {
        display: inline-block;
        font-size: 0.75rem;
        font-weight: 700;
        padding: 3px 10px;
        border-radius: 9999px;
        margin-right: 6px;
        margin-bottom: 8px;
    }
    .badge-blue { background: rgba(59, 130, 246, 0.15); color: #93C5FD; border: 1px solid rgba(59, 130, 246, 0.3); }
    .badge-indigo { background: rgba(99, 102, 241, 0.15); color: #C7D2FE; border: 1px solid rgba(99, 102, 241, 0.3); }
    .badge-green { background: rgba(16, 185, 129, 0.15); color: #6EE7B7; border: 1px solid rgba(16, 185, 129, 0.3); }
    .security-feed-item {
        background: #0B0F19;
        border: 1px solid #1F2937;
        border-radius: 8px;
        padding: 10px 14px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 8px;
    }
    .why-flagged-box {
        background: #070A12;
        border: 1px solid #1F2937;
        border-radius: 8px;
        padding: 10px 14px;
        margin-top: 10px;
    }
    .diff-old {
        background: rgba(239, 68, 68, 0.15);
        color: #F87171;
        padding: 6px 10px;
        border-radius: 6px;
        font-family: monospace;
        font-size: 0.85rem;
        margin-bottom: 4px;
    }
    .diff-new {
        background: rgba(16, 185, 129, 0.15);
        color: #34D399;
        padding: 6px 10px;
        border-radius: 6px;
        font-family: monospace;
        font-size: 0.85rem;
    }
</style>
""", unsafe_allow_html=True)

PRESET_SAMPLES = {
    "⚡ 30-Second Interview Demo (DB Password + API Key)": {
        "filename": "database_service.py",
        "lang": "python",
        "is_diff": False,
        "content": '''# Database Client Configuration
DATABASE_PASSWORD = "db_super_secret_password_987654321"
API_KEY = "sk-proj-998877665544332211aabbccddeeff00112233"
'''
    },
    "Python Service (AWS Keys + OpenAI + DB Hash)": {
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
    "Git Diff Commit (AWS Key + GitHub Token + Stripe Secret)": {
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
    "Node.js API Configuration (Stripe + Slack Token)": {
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

# Sidebar Controls
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=64)
    st.title("GitPulse Controls")
    st.markdown("**DevSecOps Pre-Commit Guardrail**")

    st.markdown("---")
    input_mode = st.radio(
        "Select Input Source:",
        ["⚡ Preset Scenarios", "📂 Upload File", "📝 Paste Code / Diff", "🔍 Git Staged Changes"],
        index=0
    )

    st.markdown("---")
    st.subheader("⚙️ Detection Settings")
    entropy_modifier = st.slider(
        "Entropy Sensitivity Offset",
        min_value=-1.0,
        max_value=1.0,
        value=0.0,
        step=0.1
    )

    target_lang = st.selectbox(
        "Remediation Target",
        ["Python (os.getenv)", "JavaScript (process.env)", "Shell (${VAR})", "Ruby (ENV['VAR'])"],
        index=0
    )
    lang_code = {
        "Python (os.getenv)": "python",
        "JavaScript (process.env)": "javascript",
        "Shell (${VAR})": "shell",
        "Ruby (ENV['VAR'])": "ruby"
    }[target_lang]

    st.markdown("---")
    st.subheader("🛡️ Git Pre-Commit Hook")
    if is_git_repo("."):
        st.success("✅ Git repository detected")
        if st.button("Install Hook to .git/hooks"):
            hook_dir = os.path.join(".git", "hooks")
            os.makedirs(hook_dir, exist_ok=True)
            hook_file = os.path.join(hook_dir, "pre-commit")
            hook_content = """#!/bin/sh
py -m gitpulse.cli --staged
exit $?
"""
            with open(hook_file, "w", encoding="utf-8", newline="\n") as f:
                f.write(hook_content)
            st.toast("Pre-commit hook installed!", icon="🛡️")
    else:
        st.info("ℹ️ Standalone mode (Not in git repository)")

    st.markdown("---")
    st.caption("Privacy & Security: Analysis runs in-memory. Never test production keys.")

# 1. Main Header: Purpose Obvious Within 5 Seconds
st.markdown("""
<div class="main-header">GitPulse — Stop Secrets Before They Reach Git</div>
<div class="sub-header">Detect hardcoded API keys, passwords and tokens before commit. Analyze risk, explain why it was flagged, and automatically generate a safe remediation patch.</div>
<div>
    <span class="badge-pill badge-blue">Secret Detection</span>
    <span class="badge-pill badge-indigo">Entropy Analysis</span>
    <span class="badge-pill badge-green">Auto Remediation</span>
</div>
""", unsafe_allow_html=True)

# 8. 30-Second Interview Demo Trigger
col_d1, col_d2 = st.columns([1, 3])
with col_d1:
    if st.button("⚡ Try Vulnerable Example (30s Demo)", type="primary", use_container_width=True):
        st.session_state["active_preset"] = "⚡ 30-Second Interview Demo (DB Password + API Key)"

# Manage state for content
active_content = ""
active_filename = "service.py"
is_diff_mode = False

if input_mode == "⚡ Preset Scenarios":
    preset_keys = list(PRESET_SAMPLES.keys())
    default_index = 0
    if "active_preset" in st.session_state and st.session_state["active_preset"] in preset_keys:
        default_index = preset_keys.index(st.session_state["active_preset"])
        
    demo_choice = st.selectbox("Choose a Scenario:", preset_keys, index=default_index)
    preset = PRESET_SAMPLES[demo_choice]
    active_content = preset["content"]
    active_filename = preset["filename"]
    is_diff_mode = preset["is_diff"]

elif input_mode == "📂 Upload File":
    uploaded_file = st.file_uploader(
        "Upload a source code file or .diff / .patch file",
        type=["py", "js", "ts", "json", "diff", "patch", "txt", "env", "yml", "yaml", "go", "rb"]
    )
    if uploaded_file:
        active_content = uploaded_file.getvalue().decode("utf-8", errors="replace")
        active_filename = uploaded_file.name
        is_diff_mode = active_filename.endswith((".diff", ".patch"))

elif input_mode == "📝 Paste Code / Diff":
    col_type1, col_type2 = st.columns([1, 1])
    with col_type1:
        paste_type = st.radio("Content Type:", ["Code Snippet", "Git Diff"], horizontal=True)
    with col_type2:
        active_filename = st.text_input("Simulated Filename:", value="app.py" if paste_type == "Code Snippet" else "staged.diff")
    
    is_diff_mode = (paste_type == "Git Diff")
    active_content = st.text_area("Paste Raw Code or Unified Diff below:", height=200, placeholder="Paste code containing secrets here...")

elif input_mode == "🔍 Git Staged Changes":
    if not is_git_repo("."):
        st.warning("⚠️ No active Git repository detected.")
    else:
        success, diff_output = get_staged_diff(".")
        if success and diff_output.strip():
            st.success("Staged changes detected in local repository.")
            active_content = diff_output
            active_filename = "staged.diff"
            is_diff_mode = True
        else:
            st.info("No staged changes (`git diff --cached`). Stage a file (`git add <file>`) to scan.")

# Run Scanner
if active_content:
    scanner = SecretScanner(entropy_threshold_modifier=entropy_modifier)
    if is_diff_mode:
        findings = scanner.scan_git_diff(active_content)
    else:
        findings = scanner.scan_content(active_content, file_path=active_filename)

    total_findings = len(findings)
    max_entropy = max([f.entropy for f in findings], default=0.0)

    # 2. Visual Security Dashboard (High Impact Result Cards)
    st.markdown("### Security Risk Posture")
    c1, c2, c3 = st.columns(3)
    
    with c1:
        st.metric("Secrets Flagged", total_findings, delta=f"{total_findings} alerts" if total_findings > 0 else "Clean", delta_color="inverse")
    with c2:
        st.metric("Peak Shannon Entropy", f"{max_entropy:.2f} bits", help="Shannon entropy > 3.8 indicates high randomness / cryptographic token.")
    with c3:
        if total_findings > 0:
            is_critical = any(f.risk_label == "CRITICAL" or f.entropy >= 4.5 for f in findings)
            risk_text = "🔴 CRITICAL" if is_critical else "🟠 HIGH"
        else:
            risk_text = "🟢 CLEAN"
        st.metric("Risk Status", risk_text)

    # Detected Secrets Summary Feed (Requirement 2)
    if findings:
        st.markdown("#### Detected Secrets Summary")
        for f in findings:
            badge_color = "red" if (f.risk_label == "CRITICAL" or f.entropy >= 4.5) else "orange"
            st.markdown(f"""
            <div class="security-feed-item">
                <div>
                    <span style="color: #F59E0B; margin-right: 6px;">⚠</span>
                    <strong>{f.rule_name}</strong>
                    <span style="color: #6B7280; font-family: monospace; font-size: 0.8rem; margin-left: 6px;">({f.file_path}:{f.line_number})</span>
                </div>
                <div style="color: {badge_color}; font-weight: bold; font-size: 0.8rem;">
                    {f.risk_label or "HIGH"}
                </div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("---")

    # 3. Explain Why Something Was Detected
    st.subheader("1. Flagged Credentials & Technical Explainability")
    reveal_secrets = st.checkbox("👁️ Reveal Plaintext Secrets (Security Audit Mode)", value=False)

    for idx, f in enumerate(findings, start=1):
        with st.expander(f"#{idx}: {f.rule_name} — {f.risk_badge} ({f.file_path}:{f.line_number})", expanded=True):
            col_l, col_r = st.columns([2, 1])
            with col_l:
                secret_str = f.secret_value if reveal_secrets else f.masked_value
                st.code(f"{f.line_content}\n# Detected: {secret_str}", language="python")
                
                # Why was this flagged? (Requirement 3)
                st.markdown("""
                <div class="why-flagged-box">
                    <strong style="color: #60A5FA; font-size: 0.8rem; text-transform: uppercase;">Why was this flagged?</strong>
                """, unsafe_allow_html=True)
                for reason in f.reasons:
                    st.markdown(f"- ✓ {reason}")
                st.markdown("</div>", unsafe_allow_html=True)

            with col_r:
                st.markdown("**Shannon Randomness:**")
                st.progress(min(1.0, f.entropy / 6.0))
                st.write(f"**{f.entropy:.3f} bits** (Threshold: `{f.threshold:.2f}` bits)")
                st.caption("Calculated via Claude Shannon's formula")
                st.text_input(f"Remediation Env Var (#{idx}):", value=f.suggested_env_var, key=f"env_input_{idx}")

    # 4. Improved Remediation Section & Transformations
    st.markdown("---")
    st.subheader("2. Auto-Remediation & Git Patch Generator")
    st.markdown("""
    **Remediation Pipeline:**
    `SECRET DETECTED` &rarr; `Explain Risk` &rarr; `Generate Remediation` &rarr; `Move secret → Environment Variable` &rarr; `Generate .env.example` &rarr; `Generate Git Patch`
    """)

    # Visual transformation (Requirement 4)
    st.markdown("#### Code Transformation Preview")
    for f in findings:
        st.markdown(f"""
        <div class="diff-old">- {f.line_content}</div>
        <div class="diff-new">+ {f.line_content.replace(f.secret_value, f'os.getenv("{f.suggested_env_var}")')}</div>
        <div style="margin-bottom: 8px;"></div>
        """, unsafe_allow_html=True)

    remediator = SecretRemediator(target_language=lang_code)
    sanitized_code, patch_text, env_example = remediator.remediate_content(
        active_content,
        findings,
        file_path=active_filename
    )

    t1, t2, t3 = st.tabs(["📄 Unified Patch (.patch)", "⚖️ Side-by-Side Comparison", "🔑 .env.example Template"])
    with t1:
        st.code(patch_text, language="diff")
    with t2:
        col_s1, col_s2 = st.columns(2)
        with col_s1:
            st.markdown("**❌ Original Code**")
            st.code(active_content, language="python")
        with col_s2:
            st.markdown("**✅ Sanitized Code**")
            st.code(sanitized_code, language="python")
    with t3:
        st.code(env_example, language="bash")

    # Approval Actions
    col_a1, col_a2 = st.columns(2)
    with col_a1:
        if st.button("✅ Approve Patch", type="primary", use_container_width=True):
            st.success("Patch Approved! Ready to commit sanitized changes.")
            st.download_button("💾 Download .patch File", patch_text, file_name=f"{active_filename}.patch", mime="text/x-diff")
            st.download_button("🔑 Download .env.example", env_example, file_name=".env.example", mime="text/plain")
    with col_a2:
        if st.button("❌ Reject / False Positive", use_container_width=True):
            st.warning("Patch rejected or flagged as false positive.")

# 5. Git Pre-Commit Hook Architecture Section
st.markdown("---")
st.subheader("3. Git Pre-Commit Lifecycle Integration")
st.markdown("""
```text
Developer writes code  ──>  git commit  ──>  GitPulse Scanner
                                                    │
                                      ┌─────────────┴─────────────┐
                                      ↓                           ↓
                                [Secret Found]              [Clean Code]
                                      │                           │
                               ⛔ BLOCK COMMIT              ✅ ALLOW COMMIT
```
""")

# 7 & 9. Detection Coverage & Architecture
st.markdown("---")
col_c1, col_c2 = st.columns(2)
with col_c1:
    st.subheader("Supported Secrets")
    st.markdown("- API keys (OpenAI, Stripe, Google, Generic)\n- Cloud credentials (AWS Access/Secret Keys)\n- Access tokens (GitHub PAT, Slack Tokens, Bearer)\n- Database passwords & connection strings\n- Private cryptographic keys & JWTs")
with col_c2:
    st.subheader("Supported Languages")
    st.markdown("- **Python** (`os.getenv(\"...\")`)\n- **JavaScript / TypeScript** (`process.env....`)\n- **Go** (`os.Getenv(\"...\")`)\n- **Shell / Bash** (`${...}`)\n- **Ruby** (`ENV[\"...\"]`)")

st.caption("GitPulse DevSecOps Guardrail • Shannon Information Entropy Secret Interceptor")
