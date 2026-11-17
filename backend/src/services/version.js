"use strict";

/* ------------------------------------------------------------------ */
/* Update check                                                        */
/*                                                                     */
/* Asks GitHub for the latest published release of this project and    */
/* caches the answer, so the browser never talks to GitHub itself and  */
/* GitHub's unauthenticated rate limit (60 req/h per IP) is never hit. */
/*                                                                     */
/* The backend only reports what the latest release is. The frontend   */
/* compares it against the version it was built with (version.json).   */
/*                                                                     */
/* Config (all optional except the repo):                              */
/*   UPDATE_CHECK_REPO            "owner/repo" on GitHub               */
/*   DISABLE_UPDATE_CHECK         "true" to turn the feature off       */
/*   UPDATE_CHECK_INTERVAL_HOURS  cache lifetime, default 6            */
/*   GITHUB_TOKEN                 only needed for a private repo       */
/* ------------------------------------------------------------------ */

const REPO = (process.env.UPDATE_CHECK_REPO || "").trim();
const DISABLED =
  String(process.env.DISABLE_UPDATE_CHECK || "").trim().toLowerCase() === "true";
const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const ENABLED = !DISABLED && REPO_RE.test(REPO);

if (!DISABLED && !ENABLED) {
  console.warn(
    "Update check is off: set UPDATE_CHECK_REPO to \"owner/repo\" (or DISABLE_UPDATE_CHECK=true to silence this)."
  );
}

const intervalHours = Number(process.env.UPDATE_CHECK_INTERVAL_HOURS);
const TTL_OK_MS =
  (Number.isFinite(intervalHours) && intervalHours > 0 ? intervalHours : 6) *
  60 * 60 * 1000;
const TTL_FAIL_MS = 15 * 60 * 1000; // after a failure, retry sooner but not on every page load
const TIMEOUT_MS = 5000;

// Plain releases only (1.1.0 or v1.1.0). GitHub's /releases/latest already skips
// drafts and pre-releases; this also ignores odd tags such as "1.1.0-rc1".
const SEMVER_RE = /^v?(\d+)\.(\d+)\.(\d+)$/;

let cache = { at: 0, ttl: 0, data: null };
let inflight = null;

async function fetchLatest() {
  const headers = {
    "User-Agent": "mailmetrix-update-check",
    Accept: "application/vnd.github+json"
  };
  if (process.env.GITHUB_TOKEN) {
    headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  }

  const res = await fetch(`https://api.github.com/repos/${REPO}/releases/latest`, {
    headers,
    signal: AbortSignal.timeout(TIMEOUT_MS)
  });

  if (res.status === 404) return null; // no published release yet
  if (!res.ok) throw new Error(`GitHub API responded ${res.status}`);

  const json = await res.json();
  const m = SEMVER_RE.exec(String(json.tag_name || "").trim());
  if (!m) return null;

  const url = typeof json.html_url === "string" ? json.html_url : "";
  return {
    latest: `${m[1]}.${m[2]}.${m[3]}`,
    releaseUrl: url.startsWith("https://github.com/") ? url : null,
    publishedAt: typeof json.published_at === "string" ? json.published_at : null
  };
}

async function getLatestRelease() {
  const base = {
    enabled: ENABLED,
    latest: null,
    releaseUrl: null,
    publishedAt: null,
    checkedAt: null
  };
  if (!ENABLED) return base;

  if (Date.now() - cache.at >= cache.ttl) {
    // One shared request even if many browsers load the page at the same moment.
    if (!inflight) {
      inflight = fetchLatest()
        .then((data) => {
          cache = { at: Date.now(), ttl: TTL_OK_MS, data };
        })
        .catch((err) => {
          // Keep serving the last good answer; an update check must never break the app.
          console.warn("Update check failed:", err.message);
          cache = { at: Date.now(), ttl: TTL_FAIL_MS, data: cache.data };
        })
        .finally(() => {
          inflight = null;
        });
    }
    await inflight;
  }

  return {
    ...base,
    ...(cache.data || {}),
    checkedAt: cache.at ? new Date(cache.at).toISOString() : null
  };
}

module.exports = { getLatestRelease };