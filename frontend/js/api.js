/**
 * NYAY-AI - Courtroom-Grade REST API Client
 * National Judicial & AI Evidence Intelligence Platform
 * Author: Antigravity / Dhananjay Sharma / Ayushi Sharma
 */

const API_BASE = "http://127.0.0.1:8000/api/v1";
const API_ROOT = "http://127.0.0.1:8000";

class NyayApiClient {
  constructor() {
    this.token = localStorage.getItem("nyay_token") || null;
    this.currentUser = JSON.parse(localStorage.getItem("nyay_user") || "null");
  }

  setSession(token, user) {
    this.token = token;
    this.currentUser = user;
    if (token) {
      localStorage.setItem("nyay_token", token);
    } else {
      localStorage.removeItem("nyay_token");
    }
    if (user) {
      localStorage.setItem("nyay_user", JSON.stringify(user));
    } else {
      localStorage.removeItem("nyay_user");
    }
  }

  clearSession() {
    this.setSession(null, null);
  }

  getHeaders(isMultipart = false) {
    const headers = {};
    if (!isMultipart) {
      headers["Content-Type"] = "application/json";
    }
    if (this.token) {
      headers["Authorization"] = `Bearer ${this.token}`;
    }
    return headers;
  }

  async request(endpoint, options = {}) {
    const isMultipart = options.body instanceof FormData;
    const headers = { ...this.getHeaders(isMultipart), ...(options.headers || {}) };
    const url = endpoint.startsWith("http") ? endpoint : `${API_BASE}${endpoint}`;

    try {
      const res = await fetch(url, {
        ...options,
        headers,
      });

      // Handle 401 Unauthorized
      if (res.status === 401 && !url.includes("/auth/login")) {
        console.warn("[NYAY-AI API] Session expired or unauthorized for:", url);
        // Dispatch session expired event so UI can react gracefully
        window.dispatchEvent(new CustomEvent("nyay:session-expired"));
      }

      if (options.asBlob) {
        if (!res.ok) {
          throw new Error(`HTTP ${res.status}: Failed to download resource`);
        }
        return await res.blob();
      }

      const contentType = res.headers.get("content-type") || "";
      let data = null;
      if (contentType.includes("application/json")) {
        data = await res.json();
      } else {
        const text = await res.text();
        try {
          data = JSON.parse(text);
        } catch {
          data = { message: text };
        }
      }

      if (!res.ok) {
        const errorMsg = data?.detail || data?.message || `Request failed with status ${res.status}`;
        const err = new Error(errorMsg);
        err.status = res.status;
        err.payload = data;
        throw err;
      }

      return data;
    } catch (err) {
      console.error(`[NYAY-AI API Error] ${options.method || "GET"} ${url}:`, err.message);
      throw err;
    }
  }

  // ==========================================
  // 1. HEALTH & SYSTEM
  // ==========================================
  async getHealth() {
    try {
      const res = await fetch(`${API_ROOT}/health`);
      return await res.json();
    } catch (err) {
      return { status: "OFFLINE", error: err.message };
    }
  }

  async getAdminSystemStatus() {
    return this.request("/rbac/admin/system/status");
  }

  async listAdminUsers() {
    return this.request("/rbac/admin/users");
  }

  // ==========================================
  // 2. AUTHENTICATION & PROFILES
  // ==========================================
  async login(username, password) {
    const res = await this.request("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    if (res?.access_token) {
      this.setSession(res.access_token, res.user);
    }
    return res;
  }

  async getProfile() {
    return this.request("/auth/me");
  }

  async registerUser(userData) {
    return this.request("/auth/register", {
      method: "POST",
      body: JSON.stringify(userData),
    });
  }

  // ==========================================
  // 3. CASES & COMMAND CENTER
  // ==========================================
  async listCases(params = {}) {
    const q = new URLSearchParams(params).toString();
    return this.request(`/cases${q ? `?${q}` : ""}`);
  }

  async getCase(caseId) {
    return this.request(`/cases/${caseId}`);
  }

  async createCase(payload) {
    return this.request("/cases", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  async updateCase(caseId, payload) {
    return this.request(`/cases/${caseId}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
  }

  async getOperationalDashboard() {
    return this.request("/cases/operational-dashboard");
  }

  async getPortfolioOverview() {
    return this.request("/cases/portfolio-overview");
  }

  async getCaseOperationalView(caseId) {
    return this.request(`/cases/${caseId}/operational-view`);
  }

  async getCaseIntelligenceSummary(caseId) {
    return this.request(`/cases/${caseId}/intelligence-summary`);
  }

  async processCasePipeline(caseId) {
    return this.request(`/cases/${caseId}/process-pipeline`, {
      method: "POST",
    });
  }

  async sealCase(caseId, payload = {}) {
    return this.request(`/cases/${caseId}/seal`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  async getSealingManifest(caseId) {
    return this.request(`/cases/${caseId}/sealing-manifest`);
  }

  async verifyCaseAdmissibility(caseId, payload = {}) {
    return this.request(`/cases/${caseId}/verify-admissibility`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  async getAdmissibilityCertificate(caseId) {
    return this.request(`/cases/${caseId}/admissibility-certificate`);
  }

  // ==========================================
  // 4. EVIDENCE VAULT
  // ==========================================
  async listEvidence(caseId = null) {
    const endpoint = caseId ? `/evidence?case_id=${encodeURIComponent(caseId)}` : "/evidence";
    return this.request(endpoint);
  }

  async getEvidence(evidenceId) {
    return this.request(`/evidence/${evidenceId}`);
  }

  async uploadEvidence(caseId, file, sourceDescription = "", clientSha256 = "") {
    const formData = new FormData();
    formData.append("case_id", caseId);
    formData.append("file", file);
    if (sourceDescription) formData.append("source_description", sourceDescription);
    if (clientSha256) formData.append("client_sha256", clientSha256);

    return this.request("/evidence/upload", {
      method: "POST",
      body: formData,
    });
  }

  async verifyEvidenceIntegrity(evidenceId) {
    return this.request(`/evidence/${evidenceId}/verify-integrity`, {
      method: "POST",
    });
  }

  // ==========================================
  // 5. FORENSIC ENGINE
  // ==========================================
  async analyzeForensics(evidenceId) {
    return this.request(`/forensics/analyze/${evidenceId}`, {
      method: "POST",
    });
  }

  async getForensicResults(evidenceId) {
    return this.request(`/forensics/${evidenceId}`);
  }

  // ==========================================
  // 6. AI INTELLIGENCE
  // ==========================================
  async analyzeAI(evidenceId) {
    return this.request(`/ai/analyze/${evidenceId}`, {
      method: "POST",
    });
  }

  async getAIResults(evidenceId) {
    return this.request(`/ai/${evidenceId}`);
  }

  // ==========================================
  // 7. CORRELATION & RELATIONSHIPS
  // ==========================================
  async getCorrelation(caseId) {
    return this.request(`/correlation/case/${caseId}`);
  }

  async triggerCorrelation(caseId) {
    return this.request("/correlation/analyze", {
      method: "POST",
      body: JSON.stringify({ case_id: caseId }),
    });
  }

  // ==========================================
  // 8. CHAIN OF CUSTODY
  // ==========================================
  async getCustodyHistory(evidenceId) {
    return this.request(`/custody/evidence/${evidenceId}`);
  }

  async verifyCustodyChain(evidenceId) {
    return this.request(`/custody/${evidenceId}/verify`, {
      method: "POST",
    });
  }

  async appendCustodyEvent(evidenceId, payload) {
    return this.request(`/custody/evidence/${evidenceId}/events`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  // ==========================================
  // 9. COURT REPORTS (BSA 2023)
  // ==========================================
  async generateCourtReport(caseId, payload = {}) {
    return this.request(`/reports/generate/${caseId}`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  async getReport(reportId) {
    return this.request(`/reports/${reportId}`);
  }

  async downloadReport(reportId) {
    return this.request(`/reports/download/${reportId}`, { asBlob: true });
  }

  // ==========================================
  // 10. JUDICIAL VERIFICATION & DISCLOSURE
  // ==========================================
  async verifyReportQR(codeOrId) {
    return this.request(`/verification/${encodeURIComponent(codeOrId)}`);
  }

  async exportBundle(caseId, payload = {}) {
    return this.request(`/cases/${caseId}/export-bundle`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  async getBundleManifest(caseId) {
    return this.request(`/cases/${caseId}/export-bundle/manifest`);
  }

  async downloadBundle(caseId) {
    return this.request(`/cases/${caseId}/download-bundle`, { asBlob: true });
  }

  async verifyBundle(caseId, payload = {}) {
    return this.request(`/cases/${caseId}/verify-bundle`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  // ==========================================
  // 11. COURTROOM EXHIBITS (PHASE 21)
  // ==========================================
  async listExhibits(caseId) {
    return this.request(`/cases/${caseId}/exhibits`);
  }

  async tenderEvidence(caseId, payload) {
    return this.request(`/cases/${caseId}/exhibits/tender`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  async markExhibit(caseId, payload) {
    return this.request(`/cases/${caseId}/exhibits/mark`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  async getExhibitDetails(caseId, exhibitNumber) {
    return this.request(`/cases/${caseId}/exhibits/${encodeURIComponent(exhibitNumber)}`);
  }

  // ==========================================
  // 12. TRIAL DISPOSITION (PHASE 22)
  // ==========================================
  async getTrialDisposition(caseId) {
    return this.request(`/cases/${caseId}/disposition`);
  }

  async pronounceVerdict(caseId, payload) {
    return this.request(`/cases/${caseId}/disposition/verdict`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  async resolveObjection(caseId, exhibitNumber, payload) {
    return this.request(`/cases/${caseId}/exhibits/${encodeURIComponent(exhibitNumber)}/resolve-objection`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  async orderExhibitDisposal(caseId, exhibitNumber, payload) {
    return this.request(`/cases/${caseId}/exhibits/${encodeURIComponent(exhibitNumber)}/disposal-order`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  async archiveCase(caseId, payload = {}) {
    return this.request(`/cases/${caseId}/archive`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  // ==========================================
  // 13. AUDIT TRAIL
  // ==========================================
  async getAuditLogs(params = {}) {
    const q = new URLSearchParams(params).toString();
    return this.request(`/audit${q ? `?${q}` : ""}`);
  }

  async getCaseAuditHistory(caseId, params = {}) {
    const q = new URLSearchParams(params).toString();
    return this.request(`/audit/cases/${caseId}${q ? `?${q}` : ""}`);
  }

  async getEvidenceAuditHistory(evidenceId, params = {}) {
    const q = new URLSearchParams(params).toString();
    return this.request(`/audit/evidence/${evidenceId}${q ? `?${q}` : ""}`);
  }

  async getReportAuditHistory(reportId, params = {}) {
    const q = new URLSearchParams(params).toString();
    return this.request(`/audit/reports/${reportId}${q ? `?${q}` : ""}`);
  }
}

// Global API instance
window.nyayApi = new NyayApiClient();
