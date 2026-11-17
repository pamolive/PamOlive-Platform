'use strict';
// Builtins only. No Playwright/npm import, UI launch, CA, TLS or CDP.
const fs = require('node:fs');
const crypto = require('node:crypto');
const {spawnSync} = require('node:child_process');
const result = {nodeVersion: process.version, browserVersion: null, certutilPresent: null,
  certutilFunctional: null, nssEmpty: null, browserPresent: null, nonroot: null,
  rootReadOnly: null, capsZero: null, noNewPrivs: null, authority: false};
function need(value, code) { if (!value) { const error = new Error(code); error.code = code; throw error; } }
function status(text) {
  return Object.fromEntries(text.trim().split('\n').map(line => {
    const colon = line.indexOf(':'); return [line.slice(0, colon), line.slice(colon + 1).trim()];
  }));
}
function executable(file) {
  const real = fs.realpathSync(file), info = fs.statSync(real);
  need(info.isFile() && info.uid === 0 && (info.mode & 0o022) === 0, 'B0_PRE_EXECUTABLE_MODE_REFUSED');
  fs.accessSync(real, fs.constants.X_OK);
  return real;
}
function command(file, args, code) {
  const response = spawnSync(file, args, {timeout: 10000, maxBuffer: 16384, encoding: 'utf8',
    env: {PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/tmp/b0-home', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8'}});
  need(!response.error && response.status === 0, code);
  return response.stdout;
}
function probe() {
  const raw = fs.readFileSync('/inputs/pins-stage0.json');
  need(raw.length <= 8192 && crypto.createHash('sha256').update(raw).digest('hex') === process.env.B0_PINS_SHA256,
    'B0_PRE_INPUT_PINS_CHANGED');
  // The same bytes were strict/schema validated on the host after the reviewed hash.
  const pins = JSON.parse(raw);
  const info = status(fs.readFileSync('/proc/self/status', 'utf8'));
  result.nonroot = process.getuid() > 0 && process.getgid() > 0;
  result.capsZero = ['CapEff', 'CapPrm', 'CapInh', 'CapAmb'].every(key => /^0+$/.test(info[key] || 'missing'));
  result.noNewPrivs = info.NoNewPrivs === '1';
  const roots = fs.readFileSync('/proc/self/mountinfo', 'utf8').trim().split('\n')
    .map(line => line.split(' ')).filter(parts => parts[4] === '/');
  result.rootReadOnly = roots.length === 1 && roots[0][5].split(',').includes('ro');
  need(result.nonroot && result.capsZero && result.noNewPrivs && result.rootReadOnly, 'B0_PRE_CONTAINER_PROFILE_REFUSED');
  need(/^v\d+\.\d+\.\d+$/.test(process.version) && Number(process.versions.node.split('.')[0]) >= pins.node_min_major,
    'B0_PRE_NODE_ENGINE_REFUSED');
  executable(process.execPath);
  need(process.env.HOME === '/tmp/b0-home', 'B0_PRE_HOME_REFUSED');
  fs.mkdirSync('/tmp/b0-home', {mode: 0o700});
  let certutil = null;
  for (const directory of ['/usr/local/bin', '/usr/bin', '/bin']) {
    if (fs.existsSync(directory + '/certutil')) { certutil = executable(directory + '/certutil'); break; }
  }
  result.certutilPresent = certutil !== null;
  need(result.certutilPresent, 'B0_PRE_CERTUTIL_MISSING');
  fs.mkdirSync('/tmp/b0-home/.pki', {mode: 0o700});
  const nss = '/tmp/b0-home/.pki/nssdb';
  fs.mkdirSync(nss, {mode: 0o700});
  result.certutilFunctional = false;
  command(certutil, ['-N', '--empty-password', '-d', 'sql:' + nss], 'B0_PRE_CERTUTIL_NSS_INIT_FAILED');
  result.certutilFunctional = true;
  const listing = command(certutil, ['-L', '-d', 'sql:' + nss], 'B0_PRE_NSS_LIST_FAILED');
  result.nssEmpty = !listing.split('\n').some(line => /\s+[A-Za-z]*,[A-Za-z]*,[A-Za-z]*\s*$/.test(line));
  need(result.nssEmpty, 'B0_PRE_NSS_NOT_EMPTY');
  const directory = '/ms-playwright/chromium-' + pins.chromium_revision;
  const candidates = ['/chrome-linux64/chrome', '/chrome-linux/chrome']
    .map(suffix => directory + suffix).filter(file => fs.existsSync(file));
  result.browserPresent = candidates.length > 0;
  need(result.browserPresent, 'B0_PRE_BROWSER_MISSING');
  need(candidates.length === 1, 'B0_PRE_BROWSER_PATH_AMBIGUOUS');
  const binary = executable(candidates[0]);
  need(binary.startsWith(directory + '/'), 'B0_PRE_BROWSER_PATH_REFUSED');
  const match = command(binary, ['--version'], 'B0_PRE_BROWSER_VERSION_PROBE_FAILED').match(/\b(\d+\.\d+\.\d+\.\d+)\b/);
  need(match && match[1] === pins.chromium_version, 'B0_PRE_BROWSER_VERSION_MISMATCH');
  result.browserVersion = match[1];
}
let code = 'B0_PRE_STAGE0_PREREQUISITES_READY', ok = false;
try { probe(); ok = true; }
catch (error) { code = typeof error.code === 'string' && /^B0_PRE_[A-Z0-9_]+$/.test(error.code)
  ? error.code : 'B0_PRE_STAGE0_REFUSED'; }
fs.writeFileSync('/evidence/stage0.json', JSON.stringify({code, ok, ...result}) + '\n', {flag: 'wx', mode: 0o600});
process.stdout.write(JSON.stringify({code, ok}) + '\n');
process.exitCode = ok ? 0 : 42;
