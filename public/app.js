// GitPulse Frontend Controller
let currentMode = "preset";
let activeFilename = "service.py";
let isDiff = false;
let findings = [];
let remediationResult = null;
let customEnvMap = {};

const PRESETS = {
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
  loadPreset();
});

function switchMode(mode) {
  currentMode = mode;
  ["preset", "upload", "paste"].forEach(m => {
    const btn = document.getElementById("tab" + m.charAt(0).toUpperCase() + m.slice(1));
    const panel = document.getElementById("panel" + m.charAt(0).toUpperCase() + m.slice(1));
    if (m === mode) {
      btn.className = "px-3 py-1.5 rounded-md bg-blue-600 text-white transition";
      panel.classList.remove("hidden");
    } else {
      btn.className = "px-3 py-1.5 rounded-md text-gray-400 hover:text-white transition";
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
  const p = PRESETS[key];
  if (!p) return;

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
  document.getElementById("statLang").innerText = lang;
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
  scanBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin text-lg"></i><span>Scanning Entropy & Signatures...</span>`;
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

    if (!res.ok) throw new Error("Scanner API failed: " + (await res.text()));

    const data = await res.json();
    findings = data.findings || [];
    
    // Update Metrics
    document.getElementById("statSecrets").innerText = data.total_secrets;
    document.getElementById("statEntropy").innerText = data.max_entropy > 0 ? `${data.max_entropy.toFixed(3)} b` : "0.0 b";
    
    const statRisk = document.getElementById("statRisk");
    if (data.total_secrets > 0) {
      statRisk.innerHTML = `<span class="text-red-400 font-bold">🚨 High Risk</span>`;
    } else {
      statRisk.innerHTML = `<span class="text-emerald-400 font-bold">✅ Safe</span>`;
    }

    renderFindings();

    // Trigger Auto-Remediation if secrets were found
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

function renderFindings() {
  const container = document.getElementById("findingsContainer");
  const reveal = document.getElementById("unmaskToggle").checked;

  if (findings.length === 0) {
    container.innerHTML = `
      <div class="text-center py-8 text-emerald-400 bg-emerald-950/20 border border-emerald-500/20 rounded-xl">
        <i class="fa-solid fa-circle-check text-2xl mb-1"></i>
        <div class="font-bold">No Hardcoded Secrets Detected!</div>
        <div class="text-xs text-gray-400 mt-1">Code conforms to DevSecOps baseline hygiene.</div>
      </div>
    `;
    return;
  }

  let html = "";
  findings.forEach((f, idx) => {
    const secretDisplay = reveal ? f.secret_value : f.masked_value;
    const entropyPct = Math.min(100, Math.round((f.entropy / 6.0) * 100));
    const badgeColor = f.entropy >= 4.2 ? "bg-red-500/20 text-red-400 border-red-500/30" : 
                       (f.entropy >= 3.6 ? "bg-amber-500/20 text-amber-400 border-amber-500/30" : "bg-blue-500/20 text-blue-400 border-blue-500/30");

    html += `
      <div class="bg-dark-900 border border-gray-800 rounded-xl p-3.5 space-y-2 hover:border-gray-700 transition">
        <div class="flex items-center justify-between">
          <div class="flex items-center space-x-2">
            <span class="text-xs font-bold text-gray-200">#${idx + 1} ${f.rule_name}</span>
            <span class="text-[10px] uppercase font-bold px-2 py-0.5 rounded border ${badgeColor}">${f.entropy_level}</span>
          </div>
          <span class="text-xs text-gray-400 font-mono">${f.file_path}:${f.line_number}</span>
        </div>

        <div class="bg-dark-800/90 rounded-lg p-2.5 font-mono text-xs text-red-300 border-l-4 border-red-500 flex justify-between items-center">
          <span class="truncate pr-2">${secretDisplay}</span>
          <span class="text-[10px] text-gray-400 font-sans">Entropy: <strong class="text-amber-400">${f.entropy.toFixed(3)}</strong> bits</span>
        </div>

        <div class="w-full bg-dark-800 rounded-full h-1.5 overflow-hidden">
          <div class="bg-gradient-to-r from-blue-500 to-red-500 h-1.5 rounded-full" style="width: ${entropyPct}%"></div>
        </div>

        <div class="flex items-center space-x-2 text-xs pt-1">
          <span class="text-gray-400 font-medium">Env Var:</span>
          <input type="text" value="${customEnvMap[f.secret_value] || f.suggested_env_var}" 
            onchange="updateCustomEnv('${f.secret_value}', this.value)"
            class="bg-dark-800 border border-gray-700 rounded px-2 py-1 text-xs text-blue-300 font-mono focus:outline-none focus:border-blue-500 flex-1">
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

// Auto-Remediation Execution
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

    // Populate Views
    document.getElementById("patchCodeBlock").innerText = remediationResult.patch_text;
    document.getElementById("sideOrigBlock").innerText = content;
    document.getElementById("sideRemBlock").innerText = remediationResult.sanitized_code;
    document.getElementById("envCodeBlock").innerText = remediationResult.env_example;

  } catch (err) {
    console.error(err);
  }
}

function switchOutputTab(tab) {
  ["diff", "side", "env"].forEach(t => {
    const btn = document.getElementById("tab" + t.charAt(0).toUpperCase() + t.slice(1));
    const view = document.getElementById("view" + t.charAt(0).toUpperCase() + t.slice(1));
    if (t === tab) {
      btn.className = "px-3 py-1 rounded bg-blue-600 text-white font-semibold";
      view.classList.remove("hidden");
    } else {
      btn.className = "px-3 py-1 rounded text-gray-400 hover:text-white font-semibold";
      view.classList.add("hidden");
    }
  });
}

// Approval Workflow
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
