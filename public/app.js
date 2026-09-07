// GitPulse Frontend Controller - DevSecOps Guardrail
let currentMode = "preset";
let activeFilename = "database_service.py";
let isDiff = false;
let findings = [];
let remediationResult = null;
let customEnvMap = {};

const PRESETS = {
  quick_demo: {
    filename: "database_service.py",
    is_diff: false,
    lang: "Python",
    content: `# Database Client Configuration
DATABASE_PASSWORD = "db_super_secret_password_987654321"
API_KEY = "sk-proj-998877665544332211aabbccddeeff00112233"
`
  },
  vulnerable_python: {
    filename: "service.py",
    is_diff: false,
    lang: "Python",
    content: `import requests

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
`
  },
  cloud_diff: {
    filename: "commit.diff",
    is_diff: true,
    lang: "Python (Diff)",
    content: `diff --git a/src/cloud_client.py b/src/cloud_client.py
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
`
  },
  js_config: {
    filename: "config.js",
    is_diff: false,
    lang: "JavaScript",
    content: `// Node.js Configuration Service
const config = {
  appName: "PaymentGatewayService",
  port: 8080,
  stripeSecretKey: "sk_live_998877665544332211aabbcc",
  slackWebhookToken: "xoxb-123456789012-123456789012-abcdef1234567890abcdef12"
};

module.exports = config;
`
  }
};

// Initialize
window.addEventListener("DOMContentLoaded", () => {
  initTheme();
  loadPreset();
});

// Theme Management (Light / Dark with localStorage & OS Preference)
function initTheme() {
  const isDark = document.documentElement.classList.contains("dark");
  updateThemeIcon(isDark);

  // Listen to OS theme changes if user has not explicitly set a preference
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", (e) => {
    if (!localStorage.getItem("gitpulse-theme")) {
      if (e.matches) {
        document.documentElement.classList.add("dark");
      } else {
        document.documentElement.classList.remove("dark");
      }
      updateThemeIcon(e.matches);
    }
  });
}

function toggleTheme() {
  const isDark = document.documentElement.classList.toggle("dark");
  localStorage.setItem("gitpulse-theme", isDark ? "dark" : "light");
  updateThemeIcon(isDark);
}

function updateThemeIcon(isDark) {
  const icon = document.getElementById("themeIcon");
  if (!icon) return;
  if (isDark) {
    // In dark mode: show Sun icon to switch to light mode
    icon.className = "fa-solid fa-sun text-amber-400 text-sm";
  } else {
    // In light mode: show Moon icon to switch to dark mode
    icon.className = "fa-solid fa-moon text-slate-700 text-sm";
  }
}

// 8. 30-Second Interview Demo Trigger
async function triggerQuickDemo() {
  document.getElementById("presetSelect").value = "quick_demo";
  switchMode("preset");
  loadPreset();
  
  // Smooth scroll to dashboard
  document.getElementById("visualDashboard").scrollIntoView({ behavior: "smooth" });

  setTimeout(() => {
    runScanner();
  }, 250);
}

function switchMode(mode) {
  currentMode = mode;
  ["preset", "upload", "paste"].forEach(m => {
    const btn = document.getElementById("tab" + m.charAt(0).toUpperCase() + m.slice(1));
    const panel = document.getElementById("panel" + m.charAt(0).toUpperCase() + m.slice(1));
    if (m === mode) {
      btn.className = "px-3 py-1.5 rounded-md bg-blue-600 text-white transition font-semibold";
      panel.classList.remove("hidden");
    } else {
      btn.className = "px-3 py-1.5 rounded-md text-slate-600 dark:text-gray-400 hover:text-slate-900 dark:hover:text-white transition font-semibold";
      panel.classList.add("hidden");
    }
  });

  if (mode === "preset") {
    loadPreset();
  } else if (mode === "upload") {
    document.getElementById("codeEditor").value = "";
    updateFileMetadata("Upload a file above", false, "Unknown");
  } else if (mode === "paste") {
    updatePastePlaceholder();
  }
}

function loadPreset() {
  const key = document.getElementById("presetSelect").value;
  const p = PRESETS[key] || PRESETS.quick_demo;

  activeFilename = p.filename;
  isDiff = p.is_diff;
  document.getElementById("codeEditor").value = p.content;
  updateFileMetadata(p.filename, p.is_diff, p.lang);
}

function handleFileUpload(event) {
  const file = event.target.files[0];
  if (!file) return;

  activeFilename = file.name;
  isDiff = file.name.endsWith(".diff") || file.name.endsWith(".patch");

  const reader = new FileReader();
  reader.onload = (e) => {
    document.getElementById("codeEditor").value = e.target.result;
    const lang = file.name.endsWith(".js") ? "JavaScript" : (file.name.endsWith(".py") ? "Python" : "Generic");
    updateFileMetadata(activeFilename, isDiff, lang);
  };
  reader.readAsText(file);
}

function updatePastePlaceholder() {
  const pasteType = document.querySelector('input[name="pasteType"]:checked').value;
  isDiff = (pasteType === "diff");
  activeFilename = isDiff ? "pasted.diff" : "snippet.py";
  updateFileMetadata(activeFilename, isDiff, isDiff ? "Diff Stream" : "Python");
}

function updateFileMetadata(filename, diffMode, lang) {
  document.getElementById("currentFilenameBadge").innerText = filename;
  const diffBadge = document.getElementById("diffBadge");
  if (diffMode) {
    diffBadge.classList.remove("hidden");
  } else {
    diffBadge.classList.add("hidden");
  }
}

// Scanner Execution
async function runScanner() {
  const content = document.getElementById("codeEditor").value.trim();
  if (!content) {
    alert("Please enter or select code to scan.");
    return;
  }

  const scanBtn = document.getElementById("scanBtn");
  const origBtnContent = scanBtn.innerHTML;
  scanBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin text-base"></i><span>Analyzing Shannon Entropy & Patterns...</span>`;
  scanBtn.disabled = true;

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        content: content,
        filename: activeFilename,
        is_diff: isDiff,
        entropy_modifier: 0.0
      })
    });

    if (!res.ok) throw new Error("Scanner API error: " + (await res.text()));

    const data = await res.json();
    findings = data.findings || [];

    // 2. Update Visual Security Dashboard
    updateVisualDashboard(data);

    // 3. Render "Why was this flagged?" Findings
    renderFindings();

    // 4. Trigger Auto-Remediation & Transformations
    if (findings.length > 0) {
      await runRemediation(content);
    } else {
      document.getElementById("remediationCard").classList.add("hidden");
    }

  } catch (err) {
    console.error(err);
    alert("Scan failed: " + err.message);
  } finally {
    scanBtn.innerHTML = origBtnContent;
    scanBtn.disabled = false;
  }
}

// 2. Visual Security Dashboard Updater
function updateVisualDashboard(data) {
  const count = data.total_secrets;
  const entropy = data.max_entropy;
  
  // Dashboard Boxes
  document.getElementById("dashSecretsCount").innerText = count;
  document.getElementById("dashEntropyVal").innerText = entropy > 0 ? `${entropy.toFixed(2)} b` : "0.0 b";

  const riskBadge = document.getElementById("dashRiskBadge");
  const riskSub = document.getElementById("dashRiskSubtitle");
  const scanStatus = document.getElementById("scanStatusIndicator");

  if (count === 0) {
    riskBadge.innerHTML = `<span class="text-emerald-600 dark:text-emerald-400">🟢 CLEAN</span>`;
    riskSub.innerText = "Commit Approved (All Clear)";
    scanStatus.innerHTML = `<span class="text-emerald-600 dark:text-emerald-400">Scan Complete: 0 alerts</span>`;
    document.getElementById("detectedFeedCard").classList.add("hidden");
  } else {
    const isCritical = findings.some(f => f.risk_label === "CRITICAL" || f.entropy >= 4.5);
    if (isCritical) {
      riskBadge.innerHTML = `<span class="text-red-600 dark:text-red-500">🔴 CRITICAL</span>`;
      riskSub.innerText = "Commit Blocked (High Security Violation)";
    } else {
      riskBadge.innerHTML = `<span class="text-amber-600 dark:text-amber-400">🟠 HIGH</span>`;
      riskSub.innerText = "Commit Blocked (Secrets Found)";
    }
    scanStatus.innerHTML = `<span class="text-red-600 dark:text-red-400 font-semibold">Scan Complete: ${count} secret(s) intercepted</span>`;

    // Populate Detected Secrets Summary Feed (Requirement 2)
    const feedCard = document.getElementById("detectedFeedCard");
    const feedList = document.getElementById("detectedFeedList");
    feedCard.classList.remove("hidden");

    let feedHtml = "";
    findings.forEach(f => {
      const isCrit = f.risk_label === "CRITICAL" || f.entropy >= 4.5;
      const badgeStyle = isCrit 
        ? "bg-red-500/15 text-red-700 dark:text-red-400 border border-red-500/30" 
        : "bg-amber-500/15 text-amber-700 dark:text-amber-400 border border-amber-500/30";
      feedHtml += `
        <div class="flex items-center justify-between bg-slate-50 dark:bg-dark-900 border border-slate-200 dark:border-gray-800 rounded-xl px-4 py-2.5 text-xs transition">
          <div class="flex items-center space-x-2.5">
            <span class="text-amber-500 text-sm">⚠</span>
            <span class="font-bold text-slate-800 dark:text-gray-200">${f.rule_name}</span>
            <span class="text-slate-400 dark:text-gray-500 font-mono text-[11px]">(${f.file_path}:${f.line_number})</span>
          </div>
          <span class="font-bold text-[10px] px-2.5 py-0.5 rounded-full uppercase ${badgeStyle}">
            ${f.risk_label || "HIGH"}
          </span>
        </div>
      `;
    });
    feedList.innerHTML = feedHtml;
  }
}

// 3. Render "Why was this flagged?" Detailed Findings
function renderFindings() {
  const container = document.getElementById("findingsContainer");
  const reveal = document.getElementById("unmaskToggle").checked;

  if (findings.length === 0) {
    container.innerHTML = `
      <div class="text-center py-12 text-emerald-700 dark:text-emerald-400 bg-emerald-50/70 dark:bg-emerald-950/20 border border-emerald-300 dark:border-emerald-500/30 rounded-2xl space-y-2">
        <i class="fa-solid fa-circle-check text-3xl text-emerald-600 dark:text-emerald-400"></i>
        <div class="font-bold text-base">No Hardcoded Secrets Detected!</div>
        <div class="text-xs text-slate-500 dark:text-gray-400">All scanned tokens satisfy entropy bounds and safe coding guidelines.</div>
      </div>
    `;
    return;
  }

  let html = "";
  findings.forEach((f, idx) => {
    const secretDisplay = reveal ? f.secret_value : f.masked_value;
    const entropyPct = Math.min(100, Math.round((f.entropy / 6.0) * 100));
    
    // Checklist reasons
    const reasons = f.reasons && f.reasons.length > 0 ? f.reasons : [
      `High Shannon entropy (${f.entropy.toFixed(2)} bits > ${f.threshold.toFixed(2)} threshold)`,
      `Credential-like identifier context`,
      `Matches known pattern signature: ${f.rule_name}`,
      `Appears directly as inline string literal in source code`
    ];

    let checklistHtml = reasons.map(r => `
      <li class="flex items-start space-x-2 text-xs text-slate-700 dark:text-gray-300">
        <i class="fa-solid fa-check text-emerald-600 dark:text-emerald-400 mt-0.5 text-[11px]"></i>
        <span>${r}</span>
      </li>
    `).join("");

    html += `
      <div class="bg-white dark:bg-dark-900 border border-slate-200 dark:border-gray-800 rounded-2xl p-5 space-y-4 hover:border-blue-400 dark:hover:border-gray-700 transition shadow-sm">
        
        <!-- Header -->
        <div class="flex items-center justify-between">
          <div class="flex items-center space-x-2.5">
            <span class="w-6 h-6 rounded-full bg-red-500/15 text-red-700 dark:text-red-400 font-bold flex items-center justify-center text-xs">#${idx + 1}</span>
            <span class="text-sm font-bold text-slate-900 dark:text-white">${f.rule_name}</span>
            <span class="text-[10px] font-bold px-2.5 py-0.5 rounded-full bg-red-500/15 text-red-700 dark:text-red-400 border border-red-500/30 uppercase">
              ${f.risk_badge || "🔴 HIGH"}
            </span>
          </div>
          <span class="text-xs text-slate-400 dark:text-gray-400 font-mono">${f.file_path}:${f.line_number}</span>
        </div>

        <!-- Secret Snippet Box -->
        <div class="bg-slate-50 dark:bg-dark-850 rounded-xl p-3.5 font-mono text-xs border-l-4 border-l-red-500 flex flex-col sm:flex-row justify-between sm:items-center gap-2">
          <div class="text-red-700 dark:text-red-300 truncate">
            <span class="text-slate-400 dark:text-gray-500 select-none">$ </span>${f.line_content}
          </div>
          <div class="text-slate-500 dark:text-gray-400 text-[11px] shrink-0">
            Entropy: <strong class="text-amber-600 dark:text-amber-400 font-bold">${f.entropy.toFixed(3)}</strong> bits
          </div>
        </div>

        <!-- Shannon Entropy Bar -->
        <div class="space-y-1">
          <div class="flex justify-between text-[11px] text-slate-500 dark:text-gray-400">
            <span>Shannon Randomness: <strong>${f.entropy.toFixed(2)} / 6.00 bits</strong></span>
            <span>Threshold: ${f.threshold.toFixed(2)} bits</span>
          </div>
          <div class="w-full bg-slate-200 dark:bg-dark-800 rounded-full h-1.5 overflow-hidden">
            <div class="bg-gradient-to-r from-blue-500 via-amber-500 to-red-500 h-1.5 rounded-full" style="width: ${entropyPct}%"></div>
          </div>
        </div>

        <!-- 3. Why was this flagged? Section (Requirement 3) -->
        <div class="bg-slate-50 dark:bg-dark-950/70 border border-slate-200 dark:border-gray-800/80 rounded-xl p-3.5 space-y-2">
          <div class="text-[11px] uppercase font-extrabold text-blue-700 dark:text-blue-400 tracking-wider flex items-center space-x-1.5">
            <i class="fa-solid fa-circle-question"></i>
            <span>Why was this flagged?</span>
          </div>
          <ul class="space-y-1.5">
            ${checklistHtml}
          </ul>
        </div>

        <!-- Editable Suggested Env Var -->
        <div class="flex items-center space-x-2 text-xs pt-1 border-t border-slate-200 dark:border-gray-800">
          <span class="text-slate-600 dark:text-gray-400 font-semibold shrink-0">Safe Env Variable:</span>
          <input type="text" value="${customEnvMap[f.secret_value] || f.suggested_env_var}" 
            onchange="updateCustomEnv('${f.secret_value}', this.value)"
            class="bg-slate-50 dark:bg-dark-800 border border-slate-300 dark:border-gray-700 rounded-lg px-3 py-1.5 text-xs text-blue-700 dark:text-blue-300 font-mono focus:outline-none focus:border-blue-500 flex-1 transition">
        </div>

      </div>
    `;
  });

  container.innerHTML = html;
}

function updateCustomEnv(secretVal, newEnvName) {
  customEnvMap[secretVal] = newEnvName.trim().toUpperCase();
  const content = document.getElementById("codeEditor").value.trim();
  runRemediation(content);
}

// 4. Auto-Remediation & Transformation Preview
async function runRemediation(content) {
  try {
    const res = await fetch("/api/remediate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        content: content,
        filename: activeFilename,
        is_diff: isDiff,
        custom_env_vars: customEnvMap,
        target_lang: null
      })
    });

    if (!res.ok) throw new Error("Remediation API error");

    remediationResult = await res.json();
    document.getElementById("remediationCard").classList.remove("hidden");

    // Populate Transformation Boxes (- old \n + new)
    renderTransformationPreview();

    // Populate Tabs
    document.getElementById("patchCodeBlock").innerText = remediationResult.patch_text;
    document.getElementById("sideOrigBlock").innerText = content;
    document.getElementById("sideRemBlock").innerText = remediationResult.sanitized_code;
    document.getElementById("envCodeBlock").innerText = remediationResult.env_example;

  } catch (err) {
    console.error(err);
  }
}

// 4. Render Transformation Preview (- old, + new)
function renderTransformationPreview() {
  const box = document.getElementById("transformationBoxes");
  let html = "";
  findings.forEach(f => {
    const envName = customEnvMap[f.secret_value] || f.suggested_env_var;
    const oldLine = f.line_content;
    let newLine = oldLine.replace(`"${f.secret_value}"`, `os.getenv("${envName}")`)
                         .replace(`'${f.secret_value}'`, `os.getenv("${envName}")`)
                         .replace(f.secret_value, `os.getenv("${envName}")`);

    html += `
      <div class="bg-slate-50 dark:bg-dark-900 border border-slate-200 dark:border-gray-800 rounded-xl p-3 space-y-1.5 transition">
        <div class="text-red-700 dark:text-red-400 bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/30 px-2.5 py-1.5 rounded-lg flex items-center text-xs font-mono">
          <span class="select-none font-bold mr-2 text-red-500">-</span>
          <span class="truncate">${oldLine}</span>
        </div>
        <div class="text-emerald-700 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-900/30 px-2.5 py-1.5 rounded-lg flex items-center text-xs font-mono">
          <span class="select-none font-bold mr-2 text-emerald-500">+</span>
          <span class="truncate">${newLine}</span>
        </div>
      </div>
    `;
  });
  box.innerHTML = html;
}

function switchOutputTab(tab) {
  ["diff", "side", "env"].forEach(t => {
    const btn = document.getElementById("tab" + t.charAt(0).toUpperCase() + t.slice(1));
    const view = document.getElementById("view" + t.charAt(0).toUpperCase() + t.slice(1));
    if (t === tab) {
      btn.className = "px-3 py-1 rounded bg-blue-600 text-white font-semibold shadow-sm";
      view.classList.remove("hidden");
    } else {
      btn.className = "px-3 py-1 rounded text-slate-600 dark:text-gray-400 hover:text-slate-900 dark:hover:text-white font-semibold";
      view.classList.add("hidden");
    }
  });
}

// 5. Pre-Commit Hook Copy Helpers
function copyPreCommitScript() {
  const script = `#!/bin/sh
# GitPulse Pre-Commit Hook (.git/hooks/pre-commit)
echo "🛡️ GitPulse: Scanning staged changes..."
py -m gitpulse.cli --staged
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
    echo "❌ COMMIT BLOCKED: Secret(s) detected!"
    exit 1
fi
exit 0`;
  navigator.clipboard.writeText(script).then(() => {
    alert("Copied GitPulse pre-commit shell script to clipboard! Save to .git/hooks/pre-commit");
  });
}

function copyPreCommitYaml() {
  const yaml = `repos:
  - repo: local
    hooks:
      - id: gitpulse-interceptor
        name: GitPulse Secret Interceptor
        entry: py -m gitpulse.cli --staged
        language: system
        stages: [commit]`;
  navigator.clipboard.writeText(yaml).then(() => {
    alert("Copied .pre-commit-config.yaml to clipboard!");
  });
}

// Approval & Downloads
function approvePatch() {
  document.getElementById("downloadsArea").classList.remove("hidden");
}

function rejectPatch() {
  document.getElementById("downloadsArea").classList.add("hidden");
  alert("Remediation was rejected or marked as false positive.");
}

function downloadFile(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function downloadPatchFile() {
  if (!remediationResult) return;
  const base = activeFilename.replace(/\.[^/.]+$/, "");
  downloadFile(remediationResult.patch_text, `${base}_sanitized.patch`, "text/x-diff");
}

function downloadSanitizedFile() {
  if (!remediationResult) return;
  downloadFile(remediationResult.sanitized_code, `sanitized_${activeFilename}`, "text/plain");
}

function downloadEnvFile() {
  if (!remediationResult) return;
  downloadFile(remediationResult.env_example, ".env.example", "text/plain");
}
