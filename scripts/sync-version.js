#!/usr/bin/env node
/**
 * Runs automatically as the npm "version" lifecycle hook, i.e. right after
 * `npm version patch|minor|major` bumps the root package.json and BEFORE npm
 * creates the git commit + tag. It keeps every part of the project in sync:
 *
 *   root package.json  (source of truth)
 *     ├─> frontend/src/version.json   (read by the footer)
 *     ├─> backend/package.json        (+ package-lock.json)
 *
 * The files it touches are `git add`-ed so they land in the same release commit.
 */
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const root = path.resolve(__dirname, '..');
const read = (p) => JSON.parse(fs.readFileSync(p, 'utf8'));
const write = (p, data) => fs.writeFileSync(p, JSON.stringify(data, null, 2) + '\n');

const { version } = read(path.join(root, 'package.json'));
const touched = [];

// 1) Frontend version file (consumed by the footer)
const frontendFile = path.join(root, 'frontend', 'src', 'version.json');
write(frontendFile, { version, buildDate: new Date().toISOString() });
touched.push(frontendFile);

// 2) Backend package.json + lock file
const backendPkg = path.join(root, 'backend', 'package.json');
if (fs.existsSync(backendPkg)) {
  const pkg = read(backendPkg);
  pkg.version = version;
  write(backendPkg, pkg);
  touched.push(backendPkg);
}

const backendLock = path.join(root, 'backend', 'package-lock.json');
if (fs.existsSync(backendLock)) {
  const lock = read(backendLock);
  lock.version = version;
  if (lock.packages && lock.packages['']) lock.packages[''].version = version;
  write(backendLock, lock);
  touched.push(backendLock);
}

// 3) Stage everything so it is part of the version commit
try {
  const files = touched.map((f) => `"${path.relative(root, f)}"`).join(' ');
  execSync(`git add ${files}`, { cwd: root, stdio: 'inherit' });
} catch (e) {
  console.warn('Could not git add version files (not a git repo?):', e.message);
}

console.log(`✔ Synced version ${version} → frontend, backend`);