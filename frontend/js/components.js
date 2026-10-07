/**
 * NYAY-AI - Reusable Component System
 * Courtroom-Grade LegalTech & Digital Forensics UI
 */

const UI = {
  // ==========================================
  // 1. TOAST NOTIFICATIONS
  // ==========================================
  toast(message, type = "info", duration = 4000) {
    let container = document.getElementById("nyay-toast-container");
    if (!container) {
      container = document.createElement("div");
      container.id = "nyay-toast-container";
      container.className = "toast-container";
      document.body.appendChild(container);
    }

    const toast = document.createElement("div");
    toast.className = `toast toast-${type} animate-slide-in`;

    const iconMap = {
      success: "✓",
      warning: "⚠",
      danger: "✕",
      info: "ℹ",
    };

    toast.innerHTML = `
      <div class="toast-icon">${iconMap[type] || "ℹ"}</div>
      <div class="toast-content">
        <div class="toast-msg">${message}</div>
      </div>
      <button class="toast-close" aria-label="Close">&times;</button>
    `;

    const closeBtn = toast.querySelector(".toast-close");
    const remove = () => {
      toast.classList.add("fade-out");
      setTimeout(() => toast.remove(), 250);
    };

    closeBtn.onclick = remove;
    container.appendChild(toast);

    if (duration > 0) {
      setTimeout(remove, duration);
    }
  },

  // ==========================================
  // 2. MODAL SYSTEM
  // ==========================================
  openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (!modal) return;
    modal.classList.add("active");
    document.body.classList.add("modal-open");

    // Close on backdrop click
    modal.onclick = (e) => {
      if (e.target === modal) {
        UI.closeModal(modalId);
      }
    };

    // Close on ESC
    const escHandler = (e) => {
      if (e.key === "Escape") {
        UI.closeModal(modalId);
        window.removeEventListener("keydown", escHandler);
      }
    };
    window.addEventListener("keydown", escHandler);
  },

  closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (!modal) return;
    modal.classList.remove("active");
    document.body.classList.remove("modal-open");
  },

  // ==========================================
  // 3. CONFIRMATION DIALOG
  // ==========================================
  confirm(options = {}) {
    return new Promise((resolve) => {
      const {
        title = "Confirm Judicial Action",
        message = "Are you sure you want to proceed with this authoritative action?",
        confirmText = "Proceed",
        cancelText = "Cancel",
        isDangerous = false,
      } = options;

      const overlay = document.createElement("div");
      overlay.className = "modal-overlay active";
      overlay.innerHTML = `
        <div class="modal-card confirm-card animate-scale-up">
          <div class="modal-header">
            <h3 class="modal-title ${isDangerous ? 'text-danger' : 'text-gold'}">${title}</h3>
            <button class="modal-close">&times;</button>
          </div>
          <div class="modal-body">
            <p class="modal-desc">${message}</p>
          </div>
          <div class="modal-footer">
            <button class="btn btn-secondary cancel-btn">${cancelText}</button>
            <button class="btn ${isDangerous ? 'btn-danger' : 'btn-primary'} confirm-btn">${confirmText}</button>
          </div>
        </div>
      `;

      const cleanup = (result) => {
        overlay.classList.remove("active");
        setTimeout(() => overlay.remove(), 200);
        resolve(result);
      };

      overlay.querySelector(".cancel-btn").onclick = () => cleanup(false);
      overlay.querySelector(".modal-close").onclick = () => cleanup(false);
      overlay.querySelector(".confirm-btn").onclick = () => cleanup(true);
      document.body.appendChild(overlay);
    });
  },

  // ==========================================
  // 4. STATUS BADGE GENERATOR
  // ==========================================
  statusBadge(status) {
    if (!status) return `<span class="badge badge-neutral">UNKNOWN</span>`;
    const s = String(status).toUpperCase();

    let type = "neutral";
    if (["OPEN", "ACTIVE", "AUTHENTIC", "VERIFIED", "ADMITTED", "ADMITTED_AS_EXHIBIT", "CONVICTED"].includes(s)) {
      type = "success";
    } else if (["UNDER_ANALYSIS", "PENDING", "MARKED_FOR_IDENTIFICATION", "PARTIALLY_CONVICTED"].includes(s)) {
      type = "warning";
    } else if (["COMPROMISED", "ANOMALY", "TAMPERED", "REJECTED", "MISMATCH"].includes(s)) {
      type = "danger";
    } else if (["COMPLETED", "OBJECTED_DECISION_RESERVED", "DISCHARGED", "DISMISSED"].includes(s)) {
      type = "info";
    } else if (["ARCHIVED", "UNSEALED"].includes(s)) {
      type = "neutral";
    }

    const label = s.replace(/_/g, " ");
    return `<span class="badge badge-${type}">${label}</span>`;
  },

  // ==========================================
  // 5. HASH DISPLAY WITH 1-CLICK COPY
  // ==========================================
  hashDisplay(hash, length = 12) {
    if (!hash) return `<span class="hash-na">N/A</span>`;
    const shortHash = hash.length > length * 2 ? `${hash.slice(0, length)}...${hash.slice(-length)}` : hash;
    return `
      <div class="hash-tag" title="Full SHA-256: ${hash}">
        <code class="hash-text">${shortHash}</code>
        <button class="hash-copy-btn" onclick="UI.copyToClipboard('${hash}', 'SHA-256 Hash copied to clipboard!')" title="Copy full cryptographic SHA-256 digest">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
          </svg>
        </button>
      </div>
    `;
  },

  copyToClipboard(text, successMsg = "Copied to clipboard!") {
    navigator.clipboard.writeText(text).then(() => {
      UI.toast(successMsg, "success", 2500);
    }).catch(() => {
      UI.toast("Failed to copy to clipboard", "danger", 2500);
    });
  },

  // ==========================================
  // 6. EMPTY STATE GENERATOR
  // ==========================================
  emptyState(title, description, icon = "⚖️", actionHtml = "") {
    return `
      <div class="empty-state">
        <div class="empty-icon">${icon}</div>
        <h3 class="empty-title">${title}</h3>
        <p class="empty-desc">${description}</p>
        ${actionHtml ? `<div class="empty-action">${actionHtml}</div>` : ""}
      </div>
    `;
  },

  // ==========================================
  // 7. LOADING SKELETON
  // ==========================================
  skeletonRows(count = 4, cols = 5) {
    let rows = "";
    for (let i = 0; i < count; i++) {
      rows += `<tr>`;
      for (let j = 0; j < cols; j++) {
        rows += `<td><div class="skeleton-bar"></div></td>`;
      }
      rows += `</tr>`;
    }
    return rows;
  },

  skeletonCards(count = 3) {
    let cards = "";
    for (let i = 0; i < count; i++) {
      cards += `
        <div class="card skeleton-card">
          <div class="skeleton-bar skeleton-title"></div>
          <div class="skeleton-bar skeleton-line"></div>
          <div class="skeleton-bar skeleton-line short"></div>
        </div>
      `;
    }
    return cards;
  },

  // ==========================================
  // 8. METRIC CARD
  // ==========================================
  metricCard(label, value, desc = "", alert = false, icon = "") {
    return `
      <div class="metric-card ${alert ? 'alert' : ''}">
        <div class="metric-header">
          <span class="metric-label">${label}</span>
          ${icon ? `<span class="metric-icon">${icon}</span>` : ""}
        </div>
        <div class="metric-value">${value}</div>
        ${desc ? `<div class="metric-desc">${desc}</div>` : ""}
      </div>
    `;
  },

  // ==========================================
  // 9. FORMATTERS
  // ==========================================
  formatDate(isoString) {
    if (!isoString) return "N/A";
    try {
      const d = new Date(isoString);
      return d.toLocaleDateString("en-IN", {
        year: "numeric",
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      });
    } catch {
      return isoString;
    }
  },

  formatBytes(bytes) {
    if (!bytes || bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  }
};

window.UI = UI;
