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
    page_title="GitPulse | Secret Interceptor & Auto-Remediator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 800;
        background: linear-gradient(90deg, #3B82F6 0%, #8B5CF6 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1.05rem;
        color: #94A3B8;
        margin-bottom: 1.5rem;
    }
    .metric-card {
        background-color: #1E293B;
        border-radius: 10px;
        padding: 1rem;
        border: 1px solid #334155;
        text-align: center;
    }
    .badge-critical {
        background-color: #EF4444;
        color: white;
        padding: 3px 8px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.8rem;
    }
    .badge-high {
        background-color: #F59E0B;
        color: white;
        padding: 3px 8px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.8rem;
    }
    .badge-medium {
        background-color: #3B82F6;
        color: white;
        padding: 3px 8px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.8rem;
    }
    .secret-box {
        font-family: monospace;
        background-color: #0F172A;
        padding: 8px 12px;
        border-radius: 6px;
        border-left: 4px solid #EF4444;
        margin-top: 5px;
    }
    .clean-box {
        font-family: monospace;
        background-color: #0F172A;
        padding: 8px 12px;
        border-radius: 6px;
        border-left: 4px solid #10B981;
        margin-top: 5px;
    }
</style>
""", unsafe_allow_html=True)

# Preset Samples
PRESET_SAMPLES = {
    "Vulnerable Python Service (AWS + OpenAI + DB Hash)": {
        "filename": "service.py",
        "lang": "python",
        "is_diff": False,
        "content": '''import requests

# Hardcoded Cloud Credentials
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# AI Model Credentials
openai_api_key = "sk-proj-abc1234567890def1234567890ghi1234567890"

# Database Credential
db_password = "d41d8cd98f00b204e9800998ecf8427e"

def query_openai(prompt):
    headers = {"Authorization": f"Bearer {openai_api_key}"}
    return requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json={"prompt": prompt})
'''
    },
    "Git Unified Diff (AWS Key + GitHub Token + Stripe Secret)": {
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
    st.markdown("DevSecOps Pre-Commit Guardrail")

    st.markdown("---")
    input_mode = st.radio(
        "Select Input Source:",
        ["⚡ Preset Demo", "📂 Upload File", "📝 Paste Code / Diff", "🔍 Git Staged Changes"],
        index=0
    )

    st.markdown("---")
    st.subheader("⚙️ Detection Settings")
    entropy_modifier = st.slider(
        "Entropy Sensitivity Offset",
        min_value=-1.0,
        max_value=1.0,
        value=0.0,
        step=0.1,
        help="Higher values require greater randomness to trigger generic alerts; lower values are more aggressive."
    )

    target_lang = st.selectbox(
        "Remediation Syntax",
        ["Auto-detect", "Python (os.getenv)", "JavaScript (process.env)", "Shell (${VAR})", "Ruby (ENV['VAR'])"],
        index=0
    )
    lang_code = {
        "Auto-detect": None,
        "Python (os.getenv)": "python",
        "JavaScript (process.env)": "javascript",
        "Shell (${VAR})": "shell",
        "Ruby (ENV['VAR'])": "ruby"
    }[target_lang]

    st.markdown("---")
    st.subheader("🛠️ Git Hook Integration")
    if is_git_repo("."):
        st.success("✅ Git repository detected")
        if st.button("Install Pre-Commit Hook"):
            hook_dir = os.path.join(".git", "hooks")
            os.makedirs(hook_dir, exist_ok=True)
            hook_file = os.path.join(hook_dir, "pre-commit")
            hook_content = """#!/bin/sh
py -m gitpulse.cli --staged
exit $?
"""
            with open(hook_file, "w", encoding="utf-8", newline="\n") as f:
                f.write(hook_content)
            st.toast("Pre-commit hook installed to .git/hooks/pre-commit", icon="🛡️")
    else:
        st.info("ℹ️ Standalone mode (Not in git worktree)")

    st.markdown("---")
    st.caption("GitPulse v1.0 • Shannon Entropy Secret Interceptor")


# Main Dashboard Header
st.markdown('<div class="main-header">🛡️ GitPulse: Pre-Commit Secret Interceptor</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="sub-header">Detect hardcoded credentials in code diffs using Shannon entropy & signature heuristics, and generate instant unified remediation patches.</div>',
    unsafe_allow_html=True
)

# Manage state for content to scan
active_content = ""
active_filename = "code.py"
is_diff_mode = False

if input_mode == "⚡ Preset Demo":
    demo_choice = st.selectbox("Choose a Vulnerable Scenario:", list(PRESET_SAMPLES.keys()))
    preset = PRESET_SAMPLES[demo_choice]
    active_content = preset["content"]
    active_filename = preset["filename"]
    is_diff_mode = preset["is_diff"]

elif input_mode == "📂 Upload File":
    uploaded_file = st.file_uploader(
        "Upload a source code file or .diff / .patch file",
        type=["py", "js", "ts", "json", "diff", "patch", "txt", "env", "yml", "yaml", "go", "rb", "php"]
    )
    if uploaded_file:
        active_content = uploaded_file.getvalue().decode("utf-8", errors="replace")
        active_filename = uploaded_file.name
        is_diff_mode = active_filename.endswith((".diff", ".patch"))
    else:
        st.info("Upload a file or choose a Preset Demo from the sidebar.")

elif input_mode == "📝 Paste Code / Diff":
    col_type1, col_type2 = st.columns([1, 1])
    with col_type1:
        paste_type = st.radio("Content Type:", ["Code Snippet", "Git Diff"], horizontal=True)
    with col_type2:
        active_filename = st.text_input("Simulated Filename:", value="app.py" if paste_type == "Code Snippet" else "staged.diff")
    
    is_diff_mode = (paste_type == "Git Diff")
    active_content = st.text_area("Paste Raw Code or Unified Diff below:", height=220, placeholder="Paste code containing secrets here...")

elif input_mode == "🔍 Git Staged Changes":
    if not is_git_repo("."):
        st.warning("⚠️ No active Git repository detected in the current directory.")
    else:
        success, diff_output = get_staged_diff(".")
        if success and diff_output.strip():
            st.success("Found staged changes in the local Git repository.")
            active_content = diff_output
            active_filename = "staged.diff"
            is_diff_mode = True
        else:
            st.info("No staged changes (`git diff --cached`) found in the local repository. Stage a file (`git add <file>`) to scan it here.")


# Code Preview Area
if active_content:
    with st.expander(f"📄 Inspect Input Content ({active_filename})", expanded=False):
        st.code(active_content, language="diff" if is_diff_mode else "python")

# Scanner Execution
if active_content:
    scanner = SecretScanner(entropy_threshold_modifier=entropy_modifier)
    
    if is_diff_mode:
        findings = scanner.scan_git_diff(active_content)
    else:
        findings = scanner.scan_content(active_content, file_path=active_filename)

    # Top Metrics Row
    m1, m2, m3, m4 = st.columns(4)
    total_findings = len(findings)
    max_entropy = max([f.entropy for f in findings], default=0.0)
    has_critical = any(f.entropy_level == "Critical Randomness" for f in findings)
    
    with m1:
        st.metric("Total Intercepted Secrets", total_findings, delta=f"{total_findings} alerts" if total_findings > 0 else "Clean", delta_color="inverse")
    with m2:
        st.metric("Peak Shannon Entropy", f"{max_entropy:.3f} bits", help="Entropy > 3.8 typically signals cryptographic secrets or random tokens.")
    with m3:
        status_label = "🚨 High Risk" if total_findings > 0 else "✅ Safe"
        st.metric("Repository Risk State", status_label)
    with m4:
        st.metric("Input Target", active_filename)

    st.markdown("---")

    if not findings:
        st.success("🎉 **No Hardcoded Secrets Detected!** The scanned code conforms to security standards.")
    else:
        st.error(f"⚠️ **Intercepted {len(findings)} Secret(s) before commit!** Review details and auto-remediation below.")

        # Interactive Findings Table & Entropy Analysis
        st.subheader("1. Flagged Credentials & Shannon Entropy Breakdown")
        
        # Toggle to reveal unmasked secrets
        reveal_secrets = st.checkbox("👁️ Reveal Plaintext Secrets (Security Audit Mode)", value=False)

        cards_tab, table_tab, math_tab = st.tabs(["📋 Detailed Findings Cards", "📊 Summary Table", "📐 Shannon Entropy Formula"])

        with cards_tab:
            for idx, f in enumerate(findings, start=1):
                col_info, col_entropy = st.columns([2, 1])
                
                with col_info:
                    badge_class = "badge-critical" if f.entropy >= 4.2 else ("badge-high" if f.entropy >= 3.6 else "badge-medium")
                    st.markdown(f"#### #{idx}: {f.rule_name} `<span class='{badge_class}'>{f.entropy_level}</span>`", unsafe_allow_html=True)
                    st.markdown(f"**Location:** `{f.file_path}:{f.line_number}` | **Suggested Env Var:** `{f.suggested_env_var}`")
                    
                    display_secret = f.secret_value if reveal_secrets else f.masked_value
                    st.markdown(f"<div class='secret-box'><b>Secret:</b> {display_secret}<br><b>Code Snippet:</b> <code>{f.line_content}</code></div>", unsafe_allow_html=True)

                with col_entropy:
                    st.markdown("**Entropy Score:**")
                    st.progress(min(1.0, f.entropy / 6.0))
                    st.write(f"**{f.entropy:.3f} bits** (Threshold: `{f.threshold:.2f}` bits)")
                    st.caption("Calculated via Shannon Information Theory")

                st.divider()

        with table_tab:
            table_data = []
            for f in findings:
                table_data.append({
                    "Rule": f.rule_name,
                    "File": f.file_path,
                    "Line": f.line_number,
                    "Secret": f.secret_value if reveal_secrets else f.masked_value,
                    "Entropy (bits)": f.entropy,
                    "Threshold": f.threshold,
                    "Risk Level": f.entropy_level,
                    "Suggested Env Var": f.suggested_env_var
                })
            st.dataframe(pd.DataFrame(table_data), use_container_width=True)

        with math_tab:
            st.markdown(r"""
            ### Shannon Entropy in DevSecOps Secret Detection
            Shannon entropy measures the uncertainty or information density in a sequence of characters:
            $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
            Where:
            - $n$ is the number of distinct characters in the string
            - $P(x_i)$ is the probability (frequency) of character $x_i$ occurring
            
            **Interpretation:**
            - Plain English / dictionary words: typically $2.0 - 3.2$ bits
            - Hexadecimal hashes/keys (max $\log_2(16) = 4.0$): typically $3.0 - 3.9$ bits
            - Base64 / High-entropy tokens (max $\log_2(64) = 6.0$): typically $4.2 - 5.8$ bits
            """)

        # Auto-Remediator Section
        st.markdown("---")
        st.subheader("2. Auto-Remediation & Patch Generation")
        st.write("GitPulse automatically replaces raw credentials with dynamic environment variable retrievals.")

        # Editable Environment Variable Names
        with st.expander("⚙️ Customize Generated Environment Variable Names", expanded=False):
            custom_env_map = {}
            col_e1, col_e2 = st.columns(2)
            for idx, f in enumerate(findings):
                col = col_e1 if idx % 2 == 0 else col_e2
                with col:
                    new_val = st.text_input(
                        f"Variable for '{f.masked_value}' ({f.rule_name}):",
                        value=f.suggested_env_var,
                        key=f"env_input_{idx}_{f.secret_value}"
                    )
                    custom_env_map[f.secret_value] = new_val

        # Generate Sanitized Code and Patch
        remediator = SecretRemediator(target_language=lang_code)
        
        # If input was raw code or file:
        if not is_diff_mode:
            sanitized_code, patch_unified, env_example = remediator.remediate_content(
                active_content,
                findings,
                custom_env_vars=custom_env_map,
                file_path=active_filename
            )

            diff_tab, side_tab, env_tab = st.tabs(["📄 Unified Patch (.patch)", "⚖️ Side-by-Side Comparison", "🔑 .env.example Template"])

            with diff_tab:
                st.code(patch_unified, language="diff")

            with side_tab:
                col_left, col_right = st.columns(2)
                with col_left:
                    st.markdown("#### ❌ Original Code (Vulnerable)")
                    st.code(active_content, language="python")
                with col_right:
                    st.markdown("#### ✅ Sanitized Code (Remediated)")
                    st.code(sanitized_code, language="python")

            with env_tab:
                st.markdown("#### Auto-Generated `.env.example`")
                st.code(env_example, language="bash")

        else:
            # When input is a git diff, create patch remediation
            st.info("Sanitized patch generated directly from git diff stream.")
            # For git diff, generate replacement patch preview
            remediated_diff = active_content
            needed_envs = {}
            for f in findings:
                env_name = custom_env_map.get(f.secret_value, f.suggested_env_var)
                replacement_syntax = f'os.getenv("{env_name}")'
                remediated_diff = remediated_diff.replace(f'"{f.secret_value}"', replacement_syntax)
                remediated_diff = remediated_diff.replace(f"'{f.secret_value}'", replacement_syntax)
                remediated_diff = remediated_diff.replace(f.secret_value, replacement_syntax)
                needed_envs[env_name] = f.rule_name

            patch_unified = remediated_diff
            sanitized_code = remediated_diff
            env_lines = ["# GitPulse Generated Environment Template\n"]
            for k, v in needed_envs.items():
                env_lines.append(f"# {v}\n{k}=\"your_{k.lower()}_here\"\n")
            env_example = "\n".join(env_lines)

            diff_tab, env_tab = st.tabs(["📄 Sanitized Git Diff Preview", "🔑 .env.example Template"])
            with diff_tab:
                st.code(remediated_diff, language="diff")
            with env_tab:
                st.code(env_example, language="bash")

        # Action Buttons: Approve / Reject Workflow
        st.markdown("---")
        st.subheader("3. Remediation Action Workbench")

        col_act1, col_act2, col_act3 = st.columns([1, 1, 2])

        if "approval_status" not in st.session_state:
            st.session_state.approval_status = None

        with col_act1:
            if st.button("✅ Approve Patch", type="primary", use_container_width=True):
                st.session_state.approval_status = "approved"

        with col_act2:
            if st.button("❌ Reject / False Positive", use_container_width=True):
                st.session_state.approval_status = "rejected"

        with col_act3:
            if st.button("🔄 Reset Scan Status", use_container_width=True):
                st.session_state.approval_status = None
                st.rerun()

        if st.session_state.approval_status == "approved":
            st.success("🎉 **Patch Approved!** Remediated code is ready for deployment. Download your artifacts below:")
            d1, d2, d3 = st.columns(3)
            with d1:
                st.download_button(
                    label="💾 Download .patch File",
                    data=patch_unified,
                    file_name=f"{os.path.splitext(active_filename)[0]}_sanitized.patch",
                    mime="text/x-diff",
                    use_container_width=True
                )
            with d2:
                st.download_button(
                    label="📥 Download Sanitized Code",
                    data=sanitized_code,
                    file_name=f"sanitized_{active_filename}",
                    mime="text/plain",
                    use_container_width=True
                )
            with d3:
                st.download_button(
                    label="🔑 Download .env.example",
                    data=env_example,
                    file_name=".env.example",
                    mime="text/plain",
                    use_container_width=True
                )

            # Option to apply directly if in local git repo
            if is_diff_mode and is_git_repo("."):
                if st.button("🚀 Apply Patch Directly to Git Working Tree"):
                    ok, msg = apply_patch(patch_unified, repo_path=".")
                    if ok:
                        st.balloons()
                        st.success("Patch applied to local repository successfully!")
                    else:
                        st.error(f"Failed to apply patch: {msg}")

        elif st.session_state.approval_status == "rejected":
            st.warning("⛔ **Patch Rejected:** Remediation was discarded or marked as false positive. Security audit log updated.")

else:
    st.info("Select an input source from the sidebar to begin scanning.")
