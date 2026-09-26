/**
 * NYAYAI - Frontend UI Controller & Application State
 * Frontend Lead: Ayushi Sharma
 */

let selectedFile = null;
let clientCalculatedHash = "";
let cachedCases = [];

document.addEventListener("DOMContentLoaded", () => {
  initNavigation();
  initDashboard();
  initIntakeHandlers();
  initCustodyHandlers();
  initReportHandlers();
});

// 1. Tab Navigation
function initNavigation() {
  const navButtons = document.querySelectorAll(".nav-item");
  const tabViews = document.querySelectorAll(".tab-view");

  navButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      const targetTab = btn.getAttribute("data-tab");
      navButtons.forEach(b => b.classList.remove("active"));
      tabViews.forEach(v => v.classList.remove("active"));

      btn.classList.add("active");
      const activeView = document.getElementById(`tab-${targetTab}`);
      if (activeView) activeView.classList.add("active");

      if (targetTab === "dashboard") loadDashboardData();
      if (targetTab === "cases") loadCasesFullView();
      if (targetTab === "intake") populateCaseDropdowns();
      if (targetTab === "reports") populateCaseDropdowns();
    });
  });

  document.getElementById("btn-quick-intake")?.addEventListener("click", () => {
    document.getElementById("nav-intake").click();
  });

  document.getElementById("btn-view-all-cases")?.addEventListener("click", () => {
    document.getElementById("nav-cases").click();
  });
}

// 2. Dashboard Loader
async function initDashboard() {
  await checkSystemHealth();
  await loadDashboardData();
}

async function checkSystemHealth() {
  try {
    const health = await api.getHealth();
    const ind = document.getElementById("system-status-indicator");
    if (health.status === "HEALTHY") {
      ind.innerHTML = `<span class="status-pulse"></span> Backend Connected (:8000)`;
    }
  } catch (err) {
    const ind = document.getElementById("system-status-indicator");
    ind.innerHTML = `<span class="status-pulse" style="background:#f43f5e; box-shadow:0 0 8px #f43f5e;"></span> Backend Offline`;
  }
}

async function loadDashboardData() {
  try {
    const res = await api.listCases();
    if (res.success) {
      cachedCases = res.data;
      document.getElementById("stat-cases-count").innerText = res.total;

      let totalEvidences = 0;
      const tbody = document.getElementById("tbody-recent-cases");
      tbody.innerHTML = "";

      if (res.data.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="text-center" style="color:var(--text-dim); padding:20px;">No cases registered yet. Create your first case.</td></tr>`;
      } else {
        res.data.slice(0, 5).forEach(c => {
          totalEvidences += c.evidence_count || 0;
          const tr = document.createElement("tr");
          tr.innerHTML = `
            <td><code>${c.case_id}</code></td>
            <td><strong>${c.title}</strong></td>
            <td>${c.jurisdiction}</td>
            <td><span class="badge badge-open">${c.status}</span></td>
            <td>${c.evidence_count} items</td>
            <td><button class="btn btn-sm btn-outline" onclick="openCaseDetails('${c.case_id}')">Open</button></td>
          `;
          tbody.appendChild(tr);
        });
      }
      document.getElementById("stat-evidence-count").innerText = totalEvidences;
    }
  } catch (err) {
    console.warn("Could not fetch cases from backend:", err);
  }
}

// 3. Cases Full View & Form
async function loadCasesFullView() {
  try {
    const res = await api.listCases();
    const tbody = document.getElementById("tbody-cases-full");
    tbody.innerHTML = "";

    if (res.data.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="text-center" style="padding:24px; color:var(--text-dim);">No cases recorded. Click '+ Create New Case' above.</td></tr>`;
      return;
    }

    res.data.forEach(c => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><code>${c.case_id}</code></td>
        <td><strong>${c.title}</strong></td>
        <td>${c.description || "N/A"}</td>
        <td>${c.jurisdiction}</td>
        <td><span class="badge badge-open">${c.status}</span></td>
        <td>${c.evidence_count} items</td>
        <td>${new Date(c.created_at).toLocaleDateString()}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error(err);
  }

  // Bind create case button
  document.getElementById("btn-open-create-case").onclick = () => {
    document.getElementById("panel-create-case").style.display = "block";
  };
  document.getElementById("btn-close-create-case").onclick = () => {
    document.getElementById("panel-create-case").style.display = "none";
  };

  document.getElementById("form-create-case").onsubmit = async (e) => {
    e.preventDefault();
    const title = document.getElementById("case-title").value;
    const desc = document.getElementById("case-description").value;
    const jur = document.getElementById("case-jurisdiction").value;

    const res = await api.createCase({ title, description: desc, jurisdiction: jur });
    if (res.success) {
      alert(`Case Docket Registered: ${res.data.case_id}`);
      document.getElementById("form-create-case").reset();
      document.getElementById("panel-create-case").style.display = "none";
      loadCasesFullView();
      loadDashboardData();
    }
  };
}

// 4. Evidence Intake & Client-Side SHA-256 Hashing
function initIntakeHandlers() {
  const dropzone = document.getElementById("evidence-dropzone");
  const fileInput = document.getElementById("evidence-file-input");
  const btnBrowse = document.getElementById("btn-browse-file");

  btnBrowse.onclick = (e) => {
    e.stopPropagation();
    fileInput.click();
  };
  dropzone.onclick = () => fileInput.click();

  dropzone.ondragover = (e) => {
    e.preventDefault();
    dropzone.style.borderColor = "var(--accent-gold)";
  };

  dropzone.ondragleave = () => {
    dropzone.style.borderColor = "rgba(212, 175, 55, 0.3)";
  };

  dropzone.ondrop = (e) => {
    e.preventDefault();
    dropzone.style.borderColor = "rgba(212, 175, 55, 0.3)";
    if (e.dataTransfer.files.length > 0) {
      handleFileSelected(e.dataTransfer.files[0]);
    }
  };

  fileInput.onchange = () => {
    if (fileInput.files.length > 0) {
      handleFileSelected(fileInput.files[0]);
    }
  };

  // Submit Intake Form
  document.getElementById("form-evidence-intake").onsubmit = async (e) => {
    e.preventDefault();
    const caseId = document.getElementById("intake-case-select").value;
    const source = document.getElementById("intake-source").value;
    const submitBtn = document.getElementById("btn-submit-intake");
    const banner = document.getElementById("intake-result-banner");

    if (!caseId || !selectedFile) {
      alert("Please select both a case and an evidence file.");
      return;
    }

    submitBtn.disabled = true;
    submitBtn.innerText = "Vaulting & Calculating SHA-256...";

    try {
      const res = await api.uploadEvidence(caseId, selectedFile, source, clientCalculatedHash);
      if (res.success) {
        banner.style.display = "block";
        banner.innerHTML = `
          <strong>Evidence Secured in Vault!</strong><br>
          Evidence ID: <code>${res.data.evidence_id}</code><br>
          Deterministic SHA-256: <code>${res.data.sha256_hash}</code><br>
          Genesis Custody Hash: <code>${res.data.genesis_event_hash}</code><br>
          <button class="btn btn-sm btn-primary" style="margin-top:10px;" onclick="runAnalysisDirectly('${res.data.evidence_id}')">
            Execute Full Forensic & AI Pipeline
          </button>
        `;
        // Pre-fill custody input
        document.getElementById("custody-evidence-id").value = res.data.evidence_id;
      }
    } catch (err) {
      alert("Upload failed: " + err.message);
    } finally {
      submitBtn.disabled = false;
      submitBtn.innerText = "Vault File & Create Genesis Custody Block";
    }
  };
}

async function handleFileSelected(file) {
  selectedFile = file;
  const precheck = document.getElementById("file-precheck-box");
  const filenameSpan = document.getElementById("precheck-filename");
  const sizeSpan = document.getElementById("precheck-size");
  const hashCode = document.getElementById("precheck-hash");
  const submitBtn = document.getElementById("btn-submit-intake");

  precheck.style.display = "block";
  filenameSpan.innerText = file.name;
  sizeSpan.innerText = `${(file.size / 1024).toFixed(2)} KB`;
  hashCode.innerText = "Computing browser WebCrypto SHA-256 fingerprint...";

  // Client-Side Cryptographic Hash calculation (Web Cryptography API)
  const arrayBuffer = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest("SHA-256", arrayBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  clientCalculatedHash = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");

  hashCode.innerText = clientCalculatedHash;
  submitBtn.disabled = false;
}

async function populateCaseDropdowns() {
  const res = await api.listCases();
  if (res.success) {
    const intakeSel = document.getElementById("intake-case-select");
    const reportSel = document.getElementById("report-case-select");
    intakeSel.innerHTML = `<option value="">-- Select Case --</option>`;
    reportSel.innerHTML = `<option value="">-- Select Case --</option>`;

    res.data.forEach(c => {
      const opt = `<option value="${c.case_id}">${c.case_id} - ${c.title}</option>`;
      intakeSel.innerHTML += opt;
      reportSel.innerHTML += opt;
    });
  }
}

// 5. Chain of Custody Inspection & Cryptographic Verification
function initCustodyHandlers() {
  document.getElementById("btn-fetch-custody").onclick = async () => {
    const evidenceId = document.getElementById("custody-evidence-id").value.trim();
    if (!evidenceId) return alert("Please specify an Evidence ID.");

    try {
      const res = await api.getCustodyLedger(evidenceId);
      renderCustodyTimeline(res);
    } catch (err) {
      alert("Failed to fetch custody ledger: " + err.message);
    }
  };

  document.getElementById("btn-verify-chain").onclick = async () => {
    const evidenceId = document.getElementById("custody-evidence-id").value.trim();
    if (!evidenceId) return alert("Please specify an Evidence ID.");

    try {
      const res = await api.verifyCustodyChain(evidenceId);
      const badge = document.getElementById("custody-verification-badge");
      if (res.is_valid) {
        badge.className = "verification-badge success";
        badge.innerText = `CRYPTOGRAPHIC INTEGRITY CONFIRMED: All ${res.verified_blocks} custody block(s) verified unbroken.`;
      } else {
        badge.className = "verification-badge danger";
        badge.innerText = `INTEGRITY COMPROMISED: ${res.diagnostic_message}`;
      }
    } catch (err) {
      alert("Verification error: " + err.message);
    }
  };
}

function renderCustodyTimeline(ledgerData) {
  const container = document.getElementById("custody-timeline");
  const badge = document.getElementById("custody-verification-badge");
  container.innerHTML = "";

  if (!ledgerData.success || ledgerData.ledger.length === 0) {
    container.innerHTML = `<p style="color:var(--text-dim);">No custody events registered for this item.</p>`;
    return;
  }

  badge.className = ledgerData.chain_intact ? "verification-badge success" : "verification-badge danger";
  badge.innerText = ledgerData.chain_intact
    ? `Chain Intact: ${ledgerData.total_events} sequentially chained block(s).`
    : `Chain Invalidation Warning!`;

  ledgerData.ledger.forEach(ev => {
    const div = document.createElement("div");
    div.className = "timeline-block";
    div.innerHTML = `
      <div class="timeline-header">
        <span class="block-title">Block #${ev.sequence_number}: ${ev.action}</span>
        <span class="block-time">${new Date(ev.timestamp).toLocaleString()}</span>
      </div>
      <div style="font-size:12px; margin-bottom:8px;">
        <strong>Actor ID:</strong> <code>${ev.actor_id}</code> | <strong>Event ID:</strong> <code>${ev.event_id}</code>
      </div>
      <div class="hash-chain-display">
        <div><span class="hash-label">Prev Hash: </span><span class="hash-val">${ev.previous_event_hash}</span></div>
        <div><span class="hash-label">Block Hash:</span><span class="hash-val">${ev.event_hash}</span></div>
      </div>
    `;
    container.appendChild(div);
  });
}

// 6. Court Reports (BSA 2023)
function initReportHandlers() {
  document.getElementById("btn-generate-report").onclick = async () => {
    const caseId = document.getElementById("report-case-select").value;
    const officerName = document.getElementById("report-officer-name").value;
    const badgeNum = document.getElementById("report-officer-badge").value;
    const jurisdiction = document.getElementById("report-jurisdiction").value;

    if (!caseId) return alert("Please select a Case Docket.");

    const res = await api.generateCourtReport(caseId, {
      certifying_officer_name: officerName,
      badge_number: badgeNum,
      jurisdiction: jurisdiction
    });

    if (res.success) {
      const out = document.getElementById("report-output-display");
      out.style.display = "block";
      out.innerHTML = `
        <div class="panel" style="border: 1px solid var(--accent-gold);">
          <h3>Official Court Admissibility Certificate (BSA 2023 / 65B)</h3>
          <p style="margin: 8px 0; font-size:13px; color:var(--text-muted);">
            Report ID: <code>${res.data.report_id}</code><br>
            SHA-256 Hash: <code>${res.data.report_sha256}</code>
          </p>
          <div style="margin-top:12px;">
            <strong>Tamper-Evident Verification Endpoint:</strong><br>
            <a href="${res.data.qr_verification_url}" target="_blank" style="color:var(--accent-blue); word-break:break-all;">
              ${res.data.qr_verification_url}
            </a>
          </div>
        </div>
      `;
    }
  };
}

// Global helper to run analysis directly
window.runAnalysisDirectly = async function(evidenceId) {
  try {
    const res = await api.triggerAnalysis(evidenceId);
    if (res.success) {
      alert(`Pipeline Executed Successfully!\nForensic Format Valid: ${res.data.forensic_report.format_valid}\nTamper Detected: ${res.data.ai_analysis.tamper_detected}\nExplanation: ${res.data.explainability.reasoning_summary}`);
      document.getElementById("nav-custody").click();
      document.getElementById("custody-evidence-id").value = evidenceId;
      document.getElementById("btn-fetch-custody").click();
    }
  } catch (err) {
    alert("Analysis failed: " + err.message);
  }
};
