import { initTabs } from "./features/tabs.js";
import { initSMTP } from "./features/smtp.js";
import { initDNS } from "./features/dns.js";
import { initHeaders } from "./features/headers.js";
import { initGenerator } from "./features/generator.js";
import { initBlacklist, renderBlacklist } from "./features/blacklist.js";
import { initScore, renderScore } from "./features/score.js";
import { initTls, renderTls } from "./features/tls.js";
import { loadSharedFromUrl } from "./features/share.js";
import { initUpdateCheck } from "./features/update.js";
import { initMobileNav } from "./features/mobile-nav.js";
import { renderSmtp, renderDns, renderGenerator, renderHeaders } from "./features/renderers.js";

initTabs();
initMobileNav();
initSMTP();
initDNS();
initHeaders();
initGenerator();
initBlacklist();
initScore();
initTls();
loadSharedFromUrl({
  blacklist: renderBlacklist,
  score: renderScore,
  tls: renderTls,
  smtp: renderSmtp,
  dns: renderDns,
  generator: renderGenerator,
  headers: renderHeaders
});

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

/* ---------------- Accessibility: mirror CSS-class state into ARIA ----------------
   tabs.js and the flow helpers signal state only through CSS classes ("active", "success",
   "error"), which assistive technology cannot see. Rather than touch every module, watch the
   classes here and reflect them as ARIA state. This works however those modules toggle them. */
(function initA11ySync() {
  const observe = (nodes, onChange) => {
    const observer = new MutationObserver((records) => records.forEach((r) => onChange(r.target)));
    nodes.forEach((node) => {
      onChange(node);
      observer.observe(node, { attributes: true, attributeFilter: ['class'] });
    });
  };

  // Sidebar tabs: the active tool is announced as the current item.
  observe(document.querySelectorAll('.tool-tabs .tab'), (tab) => {
    if (tab.classList.contains('active')) tab.setAttribute('aria-current', 'true');
    else tab.removeAttribute('aria-current');
  });

  // Workflow steps: colour alone shows progress, so add the state as visually hidden text.
  const stepText = { active: 'in progress', success: 'completed', error: 'failed' };
  const stepLabels = new Map();
  document.querySelectorAll('.flow-step').forEach((step) => {
    const label = document.createElement('span');
    label.className = 'sr-only';
    (step.querySelector('div') || step).appendChild(label);
    stepLabels.set(step, label);
  });
  observe(document.querySelectorAll('.flow-step'), (step) => {
    const state = Object.keys(stepText).find((s) => step.classList.contains(s));
    stepLabels.get(step).textContent = state ? ` (${stepText[state]})` : '';
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
    // Only show figures the backend actually reported. /api/health is intentionally minimal
    // (no process internals), so these stay "--" rather than showing invented numbers.
    if (cpuEl) {
      cpuEl.textContent = Number.isFinite(data?.cpuPercent)
        ? `${data.cpuPercent}%`
        : '--';
    }

    if (memEl) {
      memEl.textContent = Number.isFinite(data?.memory?.rssMb)
        ? `${data.memory.rssMb} MB`
        : '--';
    }
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

let telemetryInFlight = false;

async function updateBackendTelemetry() {
  if (document.hidden || telemetryInFlight) return;

  telemetryInFlight = true;
  const startTime = performance.now();

  try {
    const response = await fetch('/api/health', {
      cache: 'no-store',
      signal: AbortSignal.timeout(4000)
    });

    const duration = Math.round(performance.now() - startTime);

    if (!response.ok) throw new Error('Unhealthy response');

    const data = await response.json();

    if (data.status !== 'healthy') {
      throw new Error('Backend unhealthy');
    }

    setBackendState(true, duration, data);

  } catch {
    setBackendState(false);
  } finally {
    telemetryInFlight = false;
  }
}

updateBackendTelemetry();
setInterval(updateBackendTelemetry, 30000);
// Refresh immediately when the user comes back to the tab instead of showing stale status.
document.addEventListener('visibilitychange', () => {
  if (!document.hidden) updateBackendTelemetry();
});

/* ---------------- App version (footer) ---------------- */
// Resolves to the installed version string (or null), so the update check can reuse it.
async function loadAppVersion() {
  const el = document.getElementById('appVersion');
  if (!el) return null;
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
    return version;
  } catch (err) {
    el.hidden = true; // fail quietly — the footer simply omits the badge
    return null;
  }
}

/* ---------------- Update notification ----------------
   Compares the installed version (version.json) with the latest GitHub release,
   which the backend looks up and caches. See features/update.js. */
loadAppVersion().then((installed) => {
  if (installed) initUpdateCheck(installed);
});