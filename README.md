# 🛡️ GitPulse — Git Pre-Commit Secret Interceptor & Auto-Remediator

> **Detect → Explain → Remediate → Prevent**

GitPulse is a beginner-friendly **DevSecOps security tool** that detects hardcoded credentials in Git diffs, analyzes suspicious strings using **Shannon Entropy, pattern matching, and code context**, and automatically generates a **sanitized remediation patch** and `.env.example` template.

The goal is simple:

**Prevent secrets from accidentally entering Git version control.**

---

## 🚀 Live Demo

🌐 **Live Demo:** https://git-pulse-opal.vercel.app

💻 **GitHub:** https://github.com/Manish640326/GitPulse

---
## 🎥 Demo Video

Watch the full walkthrough here:  
[GitPulse Demo Video (Google Drive)](https://drive.google.com/drive/folders/10ujctlrAttuXb4_WgJcSfHwjRdV2eguD)

# TechVision 🚀

## Team Members
- Manish Dhami  
- Priyam Agrawal

# 🎯 Problem

Developers can accidentally commit sensitive information such as:

* API keys
* Access tokens
* Passwords
* Cloud credentials
* Private keys
* Database credentials

Once committed, these secrets can be pushed to public or private repositories and potentially be exposed to attackers.

Traditional development workflows may detect the problem only **after the secret has already entered Git history**.

### GitPulse solves this by detecting suspicious credentials **before the commit is allowed**.

---

# 💡 Solution

GitPulse combines multiple detection signals:

```text
                Git Diff / Source Code
                         │
                         ▼
                 Candidate Extraction
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
      Signature        Shannon        Context
      Matching         Entropy        Analysis
          │              │              │
          └──────────────┼──────────────┘
                         ▼
                    Risk Scoring
                         │
                         ▼
                  🚨 Secret Found
                         │
                         ▼
                  Auto Remediation
                         │
                         ▼
                 Sanitized Git Patch
                         │
                         ▼
                    Safe Commit
```

---

# ✨ Key Features

## 🔍 Dual-Engine Secret Detection

GitPulse uses two complementary detection mechanisms.

### 1. Shannon Entropy

High-randomness strings can indicate tokens, hashes, keys, and other credentials.

GitPulse calculates:

$$
H(X) = -\sum P(x_i)\log_2P(x_i)
$$

Entropy is treated as **one detection signal**, rather than proof that a string is a secret.

### 2. Curated Signature Rules

GitPulse includes pattern-based detection for common credential formats, including:

* AWS
* GitHub
* OpenAI
* Stripe
* Slack
* Google Cloud
* JWT
* Private Keys
* Generic credential patterns

---

# 🧠 Context-Aware Risk Analysis

GitPulse combines multiple signals instead of relying only on entropy.

For example:

```python
API_KEY = "FAKE_HIGH_ENTROPY_SECRET"
```

can receive a higher risk score because:

```text
✓ High entropy
✓ Credential-like variable name
✓ Token-like value
✓ Appears in an added Git line
```

This helps reduce false positives compared with using entropy alone.

---

# 🚨 Detection Example

### Vulnerable Git Diff

```diff
+ API_KEY = "FAKE_HIGH_ENTROPY_SECRET"
+ response = requests.get(API_URL)
```

GitPulse analyzes the added lines and produces a finding such as:

```text
🚨 SECRET DETECTED

Type: High-Entropy Credential
Risk: HIGH

Detection signals:
✓ High entropy
✓ Credential-like context
✓ Suspicious token structure

Recommended action:
Move the credential to an environment variable.
```

---

# ⚡ Automatic Remediation

Instead of only reporting the vulnerability, GitPulse generates a safe replacement.

### Before

```python
API_KEY = "FAKE_HIGH_ENTROPY_SECRET"
```

### After

```python
API_KEY = os.getenv("API_KEY")
```

GitPulse can also add the required import when necessary:

```python
import os
```

---

# 📄 Sanitized Patch Generation

GitPulse generates a standard unified patch.

Example:

```diff
- API_KEY = "FAKE_HIGH_ENTROPY_SECRET"
+ API_KEY = os.getenv("API_KEY")
```

The generated patch can be reviewed before being applied.

---

# 🔐 `.env.example` Generation

GitPulse also generates an environment-variable template:

```text
API_KEY=
```

The actual secret stays outside the source code.

> ⚠️ Never place real production credentials in the demo repository.

---

# 🚫 Git Pre-Commit Protection

GitPulse can be integrated directly into a Git repository using a pre-commit hook.

```text
Developer
    │
    ▼
git add .
    │
    ▼
git commit
    │
    ▼
GitPulse Pre-Commit Hook
    │
    ▼
Scan staged changes
    │
    ├───────────────┐
    ▼               ▼
Secret Found      Clean
    │               │
    ▼               ▼
Block Commit    Allow Commit
    │
    ▼
Generate Fix
```

Install the hook with:

```bash
py -m gitpulse.cli --install-hook
```

If a secret is detected, GitPulse exits with a non-zero status and the commit is aborted.

---

# 🖥️ Interactive Dashboard

GitPulse includes an interactive Streamlit interface.

The dashboard provides:

* 🔍 Code/diff scanning
* 📂 File upload
* 🎯 Preset vulnerable examples
* 📊 Secret detection results
* 📈 Shannon entropy analysis
* 🚨 Risk indicators
* 🔧 Automatic remediation
* 🔀 Side-by-side code comparison
* 📄 Unified patch generation
* 📝 `.env.example` generation
* ⬇️ Downloadable remediation artifacts

---

# 🎬 60–90 Second Demo Flow

GitPulse is designed around a simple live demonstration:

```text
1. Paste a vulnerable Git diff
             ↓
2. Click "Scan"
             ↓
3. GitPulse detects the secret
             ↓
4. Show entropy + detection reasons
             ↓
5. Generate sanitized patch
             ↓
6. Show environment-variable replacement
             ↓
7. Attempt a Git commit
             ↓
8. Pre-commit hook blocks the secret
             ↓
9. Apply remediation
             ↓
10. Commit succeeds
```

### Demo Story

**Leak → Detect → Explain → Remediate → Prevent**

---

# 🏗️ Project Architecture

```text
                         GitPulse
                            │
              ┌─────────────┴─────────────┐
              │                           │
         Streamlit UI                 CLI Tool
              │                           │
              └─────────────┬─────────────┘
                            │
                            ▼
                     Scanner Engine
                            │
             ┌──────────────┼──────────────┐
             │              │              │
             ▼              ▼              ▼
         Patterns        Entropy         Context
             │              │              │
             └──────────────┼──────────────┘
                            ▼
                       Risk Scoring
                            │
                            ▼
                    SecretFinding
                            │
                            ▼
                     Remediator
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
           Sanitized      .env.example   Patch
             Code
```

---

# 🧰 Tech Stack

| Technology          | Purpose                         |
| ------------------- | ------------------------------- |
| Python              | Core scanner and security logic |
| Streamlit           | Interactive web dashboard       |
| Regular Expressions | Credential signature detection  |
| Shannon Entropy     | Randomness analysis             |
| Git                 | Version-control integration     |
| Git Pre-Commit Hook | Commit-time protection          |
| unittest            | Automated testing               |
| Vercel              | Web deployment/API hosting      |

---

# 🚀 Quick Start

## 1. Clone the Repository

```bash
git clone https://github.com/Manish640326/GitPulse.git
cd GitPulse
```

## 2. Install Dependencies

```bash
py -m pip install -r requirements.txt
```

## 3. Launch the Streamlit Dashboard

```bash
py -m streamlit run app.py
```

Open:

```text
http://localhost:8501
```

---

# 💻 CLI Usage

## Scan a File

```bash
py -m gitpulse.cli --scan-file samples/sample_vulnerable.py
```

## Scan a Git Diff

```bash
py -m gitpulse.cli --scan-file samples/sample_aws_leak.diff
```

## Generate a Remediated File and Patch

```bash
py -m gitpulse.cli --remediate samples/sample_vulnerable.py --output samples/remediated.py --patch-out samples/patch.patch
```

## Install the Git Pre-Commit Hook

```bash
py -m gitpulse.cli --install-hook
```

After installation:

```bash
git add .
git commit -m "Add feature"
```

GitPulse automatically scans the staged changes.

If a secret is detected:

```text
❌ Secret detected
❌ Commit blocked
```

If the staged changes are clean:

```text
✓ No secrets detected
✓ Commit allowed
```

---

# 🧪 Testing

Run the automated test suite:

```bash
py -m unittest discover tests
```

The tests cover:

* Shannon entropy calculations
* Secret detection
* Git diff parsing
* Pattern matching
* Remediation
* Patch generation

---

# 📂 Project Structure

```text
GitPulse/
│
├── gitpulse/
│   ├── __init__.py
│   ├── entropy.py
│   │   └── Shannon entropy calculations
│   │
│   ├── patterns.py
│   │   └── Credential signature rules
│   │
│   ├── scanner.py
│   │   └── Diff scanning and risk analysis
│   │
│   ├── remediator.py
│   │   └── Secret replacement and patch generation
│   │
│   ├── git_utils.py
│   │   └── Git repository utilities
│   │
│   └── cli.py
│       └── Command-line interface
│
├── samples/
│   ├── sample_vulnerable.py
│   ├── sample_aws_leak.diff
│   └── sample_config.js
│
├── hooks/
│   └── pre-commit
│
├── tests/
│   ├── test_entropy.py
│   ├── test_scanner.py
│   └── test_remediator.py
│
├── app.py
├── requirements.txt
└── README.md
```

---

# 🛡️ Security Approach

GitPulse uses multiple signals to identify potential secrets:

```text
Pattern Match
      +
Shannon Entropy
      +
Code Context
      ↓
Risk Assessment
```

### Important

Entropy is not proof that a string is a credential.

For example, random-looking data can occur naturally in software. GitPulse therefore combines entropy with credential patterns and source-code context.

---

# ⚠️ Limitations

GitPulse is designed as a lightweight educational and developer-security tool.

Potential limitations include:

* Entropy-based detection can produce false positives.
* Unknown secret formats may not match curated patterns.
* Automated remediation should be reviewed before applying it to production code.
* Detection does not replace credential rotation after a real secret has been exposed.
* GitPulse should be used as one layer of a broader secure-development workflow.

---

# 🎯 Hackathon MVP

The core MVP is:

```text
Git Diff
   ↓
Secret Detection
   ↓
Shannon Entropy Analysis
   ↓
Risk Assessment
   ↓
Automatic Remediation
   ↓
Sanitized Patch
```

The Git pre-commit hook extends the MVP by preventing detected secrets from entering version control.

---

# 🌟 Why GitPulse?

GitPulse doesn't stop at:

> **"A secret was found."**

It provides a complete workflow:

> **Detect → Explain → Remediate → Prevent**

This makes GitPulse useful not only as a scanner, but as a lightweight **DevSecOps guardrail for developers**.

---

# 📌 Future Improvements

Possible future enhancements include:

* GitHub Actions integration
* Pull-request scanning
* Multi-repository scanning
* SARIF security reports
* Secret history analysis
* More credential signatures
* Additional programming-language support
* False-positive management
* Security dashboards and scan history

---

# 📄 License

This project is licensed under the **MIT License**.

See the [`LICENSE`](LICENSE) file for details.

---

## 👨‍💻 GitPulse

**Built for DevSecOps & Security**

**Detect secrets before they become security incidents.**
