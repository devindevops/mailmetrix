/* ---------------- Update notification ----------------
   Asks the backend what the latest GitHub release is and compares it with the version this
   frontend was built with. Shows a dismissible banner plus a permanent chip in the footer.
   Fails silently: an update check must never get in the way of the tools. */

const CHECK_URL = '/api/version/check';
const DISMISS_KEY = 'mm-dismissed-update';

const SEMVER_RE = /^v?(\d+)\.(\d+)\.(\d+)/;

function parseVersion(v) {
  const m = SEMVER_RE.exec(String(v || '').trim());
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

// Numeric compare, so 1.10.0 is correctly newer than 1.9.0.
function isNewer(candidate, installed) {
  const a = parseVersion(candidate);
  const b = parseVersion(installed);
  if (!a || !b) return false;
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] > b[i];
  }
  return false;
}

function getDismissed() {
  try { return localStorage.getItem(DISMISS_KEY); } catch (e) { return null; }
}

function setDismissed(version) {
  try { localStorage.setItem(DISMISS_KEY, version); } catch (e) { /* storage unavailable */ }
}

function safeReleaseUrl(url) {
  return typeof url === 'string' && url.startsWith('https://github.com/') ? url : null;
}

function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

export async function initUpdateCheck(installedVersion) {
  const banner = document.getElementById('updateBanner');
  const chip = document.getElementById('updateChip');
  if (!banner && !chip) return;

  try {
    const res = await fetch(CHECK_URL, { cache: 'no-store', signal: AbortSignal.timeout(6000) });
    if (!res.ok) return;
    const info = await res.json();
    if (!info || !info.enabled || !isNewer(info.latest, installedVersion)) return;

    const releaseUrl = safeReleaseUrl(info.releaseUrl);

    // Permanent hint next to the version badge (never dismissed).
    if (chip) {
      chip.textContent = `Update available: v${info.latest}`;
      if (releaseUrl) chip.href = releaseUrl;
      chip.classList.remove('hidden');
    }

    // Banner: shown once per new version; dismissing it hides it until a newer release exists.
    if (!banner || getDismissed() === info.latest) return;

    setText('updateTitle', `MailMetrix v${info.latest} is ready`);
    setText('updateDetail', `You're on v${installedVersion}. Update your installation to get the latest fixes and features.`);
    setText('updateFrom', `v${installedVersion}`);
    setText('updateTo', `v${info.latest}`);

    const link = document.getElementById('updateLink');
    if (link) {
      if (releaseUrl) link.href = releaseUrl;
      else link.classList.add('hidden');
    }

    const dismiss = document.getElementById('updateDismiss');
    if (dismiss) {
      dismiss.addEventListener('click', () => {
        setDismissed(info.latest);
        banner.classList.add('hidden');
      }, { once: true });
    }
    banner.classList.remove('hidden');
  } catch (e) {
    /* offline, backend down, GitHub unreachable: stay quiet */
  }
}