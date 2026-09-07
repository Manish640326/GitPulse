# 🛡️ GitPulse: Git Pre-Commit Secret Interceptor & Auto-Remediator

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Streamlit](https://img.shields.io/badge/UI-Streamlit-FF4B4B.svg)](https://streamlit.io/)
[![DevSecOps](https://img.shields.io/badge/Security-DevSecOps-success.svg)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> A beginner-friendly DevSecOps tool that intercepts hardcoded credentials before they enter git version control, measures randomness with **Shannon Entropy**, and instantly generates standardized `.patch` files and `.env.example` templates to auto-remediate vulnerabilities.

---

## 🌟 Features

- **🔍 Dual-Engine Secret Detection**:
  - **Shannon Information Entropy**: Identifies high-randomness cryptographic keys, hashes, and tokens ($H(X) \ge 3.8$).
  - **Curated Signature Rules**: Pre-configured regex matchers for AWS, GitHub, OpenAI, Stripe, Slack, Google Cloud, JWTs, and Private Keys.
- **⚡ Git Pre-Commit Guardrail**:
  - Scans `git diff --cached` staged commits in real-time.
  - Automatically aborts the commit if credentials are discovered (`exit 1`).
- **🛠️ Automated Remediation**:
  - Replaces raw literals with environment variable placeholders (e.g. `os.getenv("AWS_ACCESS_KEY_ID")` or `process.env.STRIPE_KEY`).
  - Automatically adds required imports (e.g., `import os`).
- **📄 Unified Patch & `.env.example` Generator**:
  - Emits standard `.patch` files ready for `git apply`.
  - Generates `.env.example` templates with sensible variable names.
- **🖥️ Interactive Streamlit Dashboard**:
  - 1-click Preset Demo scenarios for testing.
  - File uploader and raw code / git diff pasteboard.
  - Interactive table & visual cards with Shannon entropy score gauges.
  - Side-by-side vulnerable vs remediated code preview.
  - Instant patch approval & download workbench.

---

## 📐 The Shannon Entropy Formula

GitPulse uses Claude Shannon's Information Theory formula to determine the uncertainty and character diversity of candidate strings:

$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$

Where:
- $n$ is the count of unique characters in the token.
- $P(x_i)$ is the probability (frequency) of character $x_i$ appearing in the string.

| Character Set | Max Theoretical Entropy | GitPulse Flagging Threshold | Typical Example |
| :--- | :--- | :--- | :--- |
| **Hexadecimal** (0-9, a-f) | $4.00$ bits | $\ge 3.00$ bits | MD5/SHA hashes, Hex API keys |
| **Alphanumeric** (A-Z, a-z, 0-9) | $\sim 5.95$ bits | $\ge 3.80$ bits | Generic API tokens, secrets |
| **Base64** (A-Z, a-z, 0-9, +/=_-) | $6.00$ bits | $\ge 4.20$ bits | JWTs, AWS Secrets, Slack tokens |

---

## 🚀 Quickstart

### 1. Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/Manish640326/GitPulse.git
cd GitPulse
py -m pip install -r requirements.txt
```

### 2. Launch the Streamlit Dashboard

Run the interactive web application:

```bash
py -m streamlit run app.py
```
Open `http://localhost:8501` in your browser.

---

## 💻 CLI & Git Pre-Commit Hook Usage

GitPulse can be used in your terminal or embedded into your Git workflow:

### Scan a Specific File or Diff
```bash
# Scan a Python file
py -m gitpulse.cli --scan-file samples/sample_vulnerable.py

# Scan a git diff file
py -m gitpulse.cli --scan-file samples/sample_aws_leak.diff
```

### Remediate and Generate Patch via CLI
```bash
py -m gitpulse.cli --remediate samples/sample_vulnerable.py --output samples/remediated.py --patch-out samples/patch.patch
```

### Install Pre-Commit Hook
Install GitPulse directly into `.git/hooks/pre-commit`:
```bash
py -m gitpulse.cli --install-hook
```
Now, whenever someone runs `git commit`, GitPulse scans staged changes. If secrets are found, the commit is aborted!

---

## 🧪 Testing

Run the automated test suite covering entropy math, scanner rules, and patch generation:

```bash
py -m unittest discover tests
```

---

## 📂 Project Structure

```text
GitPulse/
├── gitpulse/
│   ├── __init__.py
│   ├── entropy.py         # Shannon entropy calculations, character set analysis & scoring
│   ├── patterns.py        # Curated regex signatures for cloud keys, tokens, and generic secrets
│   ├── scanner.py         # Code & Git diff scanner combining entropy + pattern heuristics
│   ├── remediator.py      # Automated secret replacer (os.getenv/process.env) & patch generator (.patch)
│   ├── git_utils.py       # Git repo interaction (reading staged diffs, checking working directory)
│   └── cli.py             # CLI runner suitable for git pre-commit hook execution
├── samples/               # Realistic vulnerable sample files for 1-click evaluation
│   ├── sample_vulnerable.py
│   ├── sample_aws_leak.diff
│   └── sample_config.js
├── hooks/
│   └── pre-commit         # Ready-to-use Git pre-commit hook script
├── tests/
│   ├── test_entropy.py    # Unit tests for entropy calculations
│   ├── test_scanner.py    # Unit tests for scanner rules and diff parsing
│   └── test_remediator.py # Unit tests for secret replacement and patch creation
├── app.py                 # Streamlit UI Dashboard
├── requirements.txt
└── README.md
```

---

## 🛡️ License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
