import { initTabs } from "./features/tabs.js";
import { initSMTP } from "./features/smtp.js";
import { initDNS } from "./features/dns.js";
import { initHeaders } from "./features/headers.js";
import { initGenerator } from "./features/generator.js";

initTabs();
initSMTP();
initDNS();
initHeaders();
initGenerator();

/* ---------------- Theme toggle ---------------- */
(function initTheme() {
  const root = document.documentElement;
  const btn = document.getElementById('themeToggle');
  if (!btn) return;

  btn.addEventListener('click', () => {
    const current =
      root.getAttribute('data-theme') ||
      (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    const next = current === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    try { localStorage.setItem('mm-theme', next); } catch (e) { /* storage unavailable */ }
  });
})();

/* ---------------- SMTP provider presets ---------------- */
(function initPresets() {
  const row = document.getElementById('smtpPresets');
  if (!row) return;

  row.addEventListener('click', (e) => {
    const btn = e.target.closest('.chip-button');
    if (!btn) return;

    const host = document.getElementById('smtpHost');
    const port = document.getElementById('smtpPort');
    const security = document.getElementById('smtpSecurity');

    if (host) host.value = btn.dataset.host || '';
    if (port) port.value = btn.dataset.port || '587';
    if (security && btn.dataset.security) {
      security.value = btn.dataset.security;
      // Let any existing listeners (e.g. port sync) react, then restore preset port
      security.dispatchEvent(new Event('change', { bubbles: true }));
      if (port) port.value = btn.dataset.port || port.value;
    }
    if (host) host.dispatchEvent(new Event('input', { bubbles: true }));
    document.getElementById('smtpUser')?.focus();
  });
})();

/* ---------------- Backend telemetry ---------------- */
function setBackendState(online, duration, data) {
  const latencyEl = document.getElementById('backendLatency');
  const streamEl = document.getElementById('streamStatus');
  const cpuEl = document.getElementById('containerCpu');
  const memEl = document.getElementById('containerMem');
  const statusVal = document.getElementById('backendStatus');
  const backendDot = document.getElementById('backendDot');

  if (online) {
    if (latencyEl) {
      latencyEl.textContent = `${duration}ms`;
      latencyEl.style.color = duration < 150 ? 'var(--success)' : 'var(--warning)';
    }
    if (streamEl) {
      streamEl.textContent = '● Connected';
      streamEl.style.color = 'var(--success)';
    }
    if (cpuEl) cpuEl.textContent = (data && data.cpu) || '0.5 %';
    if (memEl) memEl.textContent = (data && data.memory) || '35.0 MB';
    if (statusVal) {
      statusVal.textContent = 'Healthy';
      statusVal.classList.remove('is-down');
      statusVal.classList.add('is-healthy');
    }
    if (backendDot) backendDot.className = 'status-dot online';
  } else {
    if (latencyEl) {
      latencyEl.textContent = '-- ms';
      latencyEl.style.color = '';
    }
    if (streamEl) {
      streamEl.textContent = '● Offline';
      streamEl.style.color = 'var(--danger)';
    }
    if (cpuEl) cpuEl.textContent = '--';
    if (memEl) memEl.textContent = '--';
    if (statusVal) {
      statusVal.textContent = 'Offline';
      statusVal.classList.remove('is-healthy');
      statusVal.classList.add('is-down');
    }
    if (backendDot) backendDot.className = 'status-dot offline';
  }
}

async function updateBackendTelemetry() {
  const startTime = performance.now();
  try {
    const response = await fetch('/api/health');
    const duration = Math.round(performance.now() - startTime);

    if (!response.ok) throw new Error('Unhealthy response');
    const data = await response.json();
    setBackendState(true, duration, data);
  } catch (err) {
    setBackendState(false);
  }
}

updateBackendTelemetry();
setInterval(updateBackendTelemetry, 5000);

/* ---------------- App version (footer) ---------------- */
async function loadAppVersion() {
  const el = document.getElementById('appVersion');
  if (!el) return;
  try {
    // no-store so a new release shows immediately, even behind nginx/browser caching
    const res = await fetch('version.json', { cache: 'no-store' });
    if (!res.ok) throw new Error('version.json not found');
    const { version, buildDate } = await res.json();
    if (!version) throw new Error('no version field');

    el.textContent = `v${version}`;
    if (buildDate) {
      const d = new Date(buildDate);
      if (!isNaN(d)) el.title = `Version ${version} · released ${d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })}`;
    }
    el.hidden = false;
  } catch (err) {
    el.hidden = true; // fail quietly — the footer simply omits the badge
  }
}
loadAppVersion();