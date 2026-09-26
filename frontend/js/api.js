/**
 * NYAYAI - Frontend REST API Service
 * Frontend Lead: Ayushi Sharma
 */

const API_BASE = "http://127.0.0.1:8000/api/v1";

const api = {
  async getHealth() {
    const res = await fetch("http://127.0.0.1:8000/health");
    return res.json();
  },

  async listCases() {
    const res = await fetch(`${API_BASE}/cases`);
    return res.json();
  },

  async getCase(caseId) {
    const res = await fetch(`${API_BASE}/cases/${caseId}`);
    return res.json();
  },

  async createCase(payload) {
    const res = await fetch(`${API_BASE}/cases`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    return res.json();
  },

  async uploadEvidence(caseId, file, sourceDescription, clientSha256) {
    const formData = new FormData();
    formData.append("file", file);
    if (sourceDescription) formData.append("source_description", sourceDescription);
    if (clientSha256) formData.append("client_sha256", clientSha256);

    const res = await fetch(`${API_BASE}/cases/${caseId}/evidence`, {
      method: "POST",
      body: formData
    });
    return res.json();
  },

  async triggerAnalysis(evidenceId) {
    const res = await fetch(`${API_BASE}/evidence/${evidenceId}/analyze`, {
      method: "POST"
    });
    return res.json();
  },

  async getCustodyLedger(evidenceId) {
    const res = await fetch(`${API_BASE}/evidence/${evidenceId}/custody`);
    return res.json();
  },

  async verifyCustodyChain(evidenceId) {
    const res = await fetch(`${API_BASE}/evidence/${evidenceId}/custody/verify`, {
      method: "POST"
    });
    return res.json();
  },

  async generateCourtReport(caseId, payload) {
    const res = await fetch(`${API_BASE}/cases/${caseId}/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    return res.json();
  },

  async verifyReportQR(reportId) {
    const res = await fetch(`${API_BASE}/reports/verify/${reportId}`);
    return res.json();
  }
};
