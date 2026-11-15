'use strict';
// File data only. Never import a shell/process/network/browser/NSS package.
const fs = require('node:fs');
const crypto = require('node:crypto');
const path = require('node:path').posix;
const {TextDecoder} = require('node:util');

const KEYRING = '/usr/share/keyrings/ubuntu-archive-keyring.gpg';
const OS_PATHS = ['/etc/os-release', '/usr/lib/os-release'];
const SOURCE_DIR = '/etc/apt/sources.list.d';
const TRUST_DIR = '/etc/apt/trusted.gpg.d';
const TRUST_FILES = ['ubuntu-keyring-2012-archive.gpg', 'ubuntu-keyring-2018-archive.gpg'];
const TOOLS = ['/usr/bin/certutil', '/usr/bin/apt-get', '/usr/bin/apt-config',
  '/usr/bin/dpkg', '/usr/bin/dpkg-deb', '/usr/bin/gpgv', '/usr/bin/sqv'];
const NSS = ['libnss3.so', 'libnssutil3.so', 'libsmime3.so', 'libssl3.so', 'libnspr4.so',
  'libplc4.so', 'libplds4.so', 'libsoftokn3.so', 'libfreebl3.so', 'libfreeblpriv3.so', 'libnssckbi.so']
  .map(name => '/usr/lib/x86_64-linux-gnu/' + name);
const FIXED = new Set([...OS_PATHS, ...TOOLS, ...NSS, KEYRING, '/etc/apt/sources.list',
  '/etc/apt/trusted.gpg', '/var/lib/dpkg/status', '/var/lib/dpkg/arch',
  ...TRUST_FILES.map(name => TRUST_DIR + '/' + name)]);
const IMAGE = 'mcr.microsoft.com/playwright@sha256:ee15712262f017b8157421b212b12099146645f44b1bc5c0514cbbe6a229b1d0';
const CONFIG = 'sha256:a0d7b2b49ffa0e99787a00b7ec2af46eca58020082713f002ca9f0f1cfd1a017';
const LIMIT = 700 * 1024;
function need(value, code) { if (!value) { const error = new Error(code); error.code = code; throw error; } }
function sha(data) { return crypto.createHash('sha256').update(data).digest('hex'); }
function text(data) { try { return new TextDecoder('utf-8', {fatal: true}).decode(data); }
  catch (_) { need(false, 'B0_FACTS_UTF8_REFUSED'); } }
function clean(value, maximum = 8192) {
  need(typeof value === 'string' && Buffer.byteLength(value) <= maximum &&
    !/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(value), 'B0_FACTS_TEXT_REFUSED');
  return value;
}
function allowed(file) {
  return FIXED.has(file) || (path.dirname(file) === SOURCE_DIR && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,120}\.(list|sources)$/.test(path.basename(file))) ||
    (path.dirname(file) === '/usr/lib/x86_64-linux-gnu' && /^lib(?:nss3|nssutil3|smime3|ssl3|nspr4|plc4|plds4|softokn3|freebl3|freeblpriv3|nssckbi)\.so(?:\.\d+)*$/.test(path.basename(file)));
}
function metadata(info) {
  return {type: info.isFile() ? 'file' : info.isDirectory() ? 'dir' : info.isSymbolicLink() ? 'symlink' : 'unsupported',
    mode: '0' + Number(info.mode & 0o7777n).toString(8), uid: Number(info.uid), gid: Number(info.gid),
    nlink: Number(info.nlink), size: Number(info.size), device: String(info.dev), inode: String(info.ino)};
}
function same(a, b) { return ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size'].every(key => a[key] === b[key]); }
function reader(io = fs) {
  let total = 0;
  const links = [];
  function stat(file) { try { return io.lstatSync(file, {bigint: true}); }
    catch (error) { if (error.code === 'ENOENT') return null; need(false, 'B0_FACTS_STAT_REFUSED'); } }
  function resolve(file) {
    need(allowed(file), 'B0_FACTS_PATH_REFUSED');
    let current = file;
    const seen = new Set();
    const chain = [];
    for (let hop = 0; hop <= 8; hop++) {
      need(!seen.has(current), 'B0_FACTS_LINK_CYCLE'); seen.add(current);
      const parts = current.split('/').filter(Boolean);
      let restarted = false, terminal = null;
      for (let i = 0; i < parts.length; i++) {
        const prefix = '/' + parts.slice(0, i + 1).join('/');
        const info = stat(prefix);
        if (!info) return {path: file, present: false, resolved_path: current, chain};
        need(info.uid === 0n && info.gid === 0n && (info.isSymbolicLink() || (info.mode & 0o022n) === 0n), 'B0_FACTS_PUBLIC_METADATA_REFUSED');
        if (info.isSymbolicLink()) {
          need(hop < 8, 'B0_FACTS_LINK_DEPTH');
          const target = io.readlinkSync(prefix);
          need(typeof target === 'string' && target.length <= 512 && !/[\x00-\x20\x7f\\]/.test(target), 'B0_FACTS_LINK_TARGET_REFUSED');
          if (i < parts.length - 1) {
            const aliases = {'/bin': 'usr/bin', '/sbin': 'usr/sbin', '/lib': 'usr/lib', '/lib64': 'usr/lib64'};
            need(aliases[prefix] && (target === aliases[prefix] || target === '/' + aliases[prefix]), 'B0_FACTS_ANCESTOR_ALIAS_REFUSED');
          }
          const next = path.resolve(path.dirname(prefix), target, ...parts.slice(i + 1));
          need(allowed(next), 'B0_FACTS_LINK_SCOPE_REFUSED');
          chain.push({path: prefix, target, metadata: metadata(info)});
          current = next; restarted = true; break;
        }
        if (i < parts.length - 1) need(info.isDirectory(), 'B0_FACTS_PARENT_TYPE_REFUSED');
        else terminal = info;
      }
      if (!restarted) {
        links.push(...chain);
        return {path: file, present: true, resolved_path: current, chain, info: terminal};
      }
    }
    need(false, 'B0_FACTS_LINK_DEPTH');
  }
  function read(file, maximum, keep = true) {
    const result = resolve(file);
    if (!result.present) return {fact: result, data: null};
    const before = result.info;
    need(before.isFile() && before.nlink === 1n && before.size >= 0n && before.size <= BigInt(maximum), 'B0_FACTS_FILE_TYPE_OR_BUDGET');
    need(total + Number(before.size) <= 64 * 1024**2, 'B0_FACTS_HASH_TOTAL_BUDGET');
    const flags = io.constants.O_RDONLY | (io.constants.O_NOFOLLOW || 0) | (io.constants.O_NONBLOCK || 0);
    let fd;
    try {
      fd = io.openSync(result.resolved_path, flags);
      const opened = io.fstatSync(fd, {bigint: true});
      need(opened.isFile() && opened.nlink === 1n && same(before, opened), 'B0_FACTS_OPEN_IDENTITY_REFUSED');
      const buffer = Buffer.alloc(Math.min(32768, maximum + 1));
      const hash = crypto.createHash('sha256'), chunks = [];
      let count = 0;
      while (true) {
        const remaining = maximum - count;
        const request = Math.min(buffer.length, remaining || 1);
        const got = io.readSync(fd, buffer, 0, request, null);
        need(Number.isInteger(got) && got >= 0 && got <= request, 'B0_FACTS_READ_CONTRACT');
        if (got === 0) break;
        need(remaining > 0 && count + got <= maximum, 'B0_FACTS_FILE_GROWTH_REFUSED');
        count += got; total += got;
        need(total <= 64 * 1024**2, 'B0_FACTS_HASH_TOTAL_BUDGET');
        const block = buffer.subarray(0, got);
        hash.update(block);
        if (keep) chunks.push(Buffer.from(block));
      }
      need(count === Number(opened.size) && same(opened, io.fstatSync(fd, {bigint: true})), 'B0_FACTS_POST_READ_CHANGED');
      return {fact: {path: file, present: true, resolved_path: result.resolved_path, chain: result.chain,
        metadata: metadata(opened), sha256: hash.digest('hex')}, data: keep ? Buffer.concat(chunks, count) : null};
    } finally { if (fd !== undefined) io.closeSync(fd); }
  }
  function directory(directoryName, maximum, accept) {
    need(directoryName === SOURCE_DIR || directoryName === TRUST_DIR, 'B0_FACTS_DIRECTORY_SCOPE');
    for (const prefix of ['/', ...directoryName.split('/').filter(Boolean).map((_, i, parts) => '/' + parts.slice(0, i + 1).join('/'))]) {
      const info = stat(prefix);
      if (!info) return {present: false, entries: []};
      need(info.isDirectory() && info.uid === 0n && info.gid === 0n && (info.mode & 0o022n) === 0n, 'B0_FACTS_DIRECTORY_METADATA');
    }
    const names = [], seen = new Set();
    const directory = io.opendirSync(directoryName, {bufferSize: 1});
    try {
      while (true) {
        const entry = directory.readSync();
        if (entry === null) break;
        need(names.length < maximum && !seen.has(entry.name), 'B0_FACTS_DIRECTORY_BUDGET');
        need(accept(entry.name), 'B0_FACTS_DIRECTORY_ENTRY_REFUSED');
        seen.add(entry.name); names.push(entry.name);
      }
    } finally { directory.closeSync(); }
    return {present: true, entries: names.sort().map(name => directoryName + '/' + name)};
  }
  return {read, directory, total: () => total};
}
function* physicalLines(data, maximum = 65536) {
  const source = text(data);
  need(!source.includes('\0'), 'B0_FACTS_NUL_REFUSED');
  let start = 0;
  while (start <= source.length) {
    const end = source.indexOf('\n', start);
    const segment = source.slice(start, end < 0 ? source.length : end + 1);
    const rawBytes = Buffer.byteLength(segment);
    need(rawBytes <= maximum, 'B0_FACTS_LINE_BUDGET');
    let line = end < 0 ? segment : segment.slice(0, -1);
    if (line.endsWith('\r')) line = line.slice(0, -1);
    yield {line, rawBytes};
    if (end < 0) break;
    start = end + 1;
  }
}
function* lines(data, maximum = 65536) { for (const row of physicalLines(data, maximum)) yield row.line; }
function osFacts(data) {
  const fields = Object.create(null), selected = new Set(['ID', 'VERSION_ID', 'VERSION_CODENAME', 'UBUNTU_CODENAME', 'ID_LIKE']);
  for (const line of lines(data, 4096)) {
    if (!line || line.startsWith('#')) continue;
    const match = line.match(/^([A-Z_][A-Z0-9_]*)=(.*)$/);
    need(match && !Object.hasOwn(fields, match[1]), 'B0_FACTS_OS_SYNTAX');
    fields[match[1]] = null;
    if (!selected.has(match[1])) continue;
    let value = match[2];
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    need(/^[A-Za-z0-9._ -]{1,128}$/.test(value), 'B0_FACTS_OS_VALUE');
    fields[match[1]] = value;
  }
  return Object.fromEntries(Object.entries(fields).filter(([key]) => selected.has(key)));
}
function deb822(data, maxLine = 65536, stanzaLimit = 256 * 1024, maxRecords = 2048) {
  const result = []; let row = Object.create(null), key = null, size = 0;
  function flush() {
    if (Object.keys(row).length) { need(result.length < maxRecords, 'B0_FACTS_RECORD_COUNT'); result.push(row); }
    row = Object.create(null); key = null; size = 0;
  }
  for (const {line, rawBytes} of physicalLines(data, maxLine)) {
    size += rawBytes;
    need(size <= stanzaLimit, 'B0_FACTS_STANZA_BUDGET');
    if (!line) { flush(); continue; }
    if (line.startsWith('#')) continue;
    if (/^[ \t]/.test(line)) { need(key, 'B0_FACTS_ORPHAN_CONTINUATION'); row[key] += ' ' + line.trim(); continue; }
    const match = line.match(/^([A-Za-z][A-Za-z0-9-]*):[ \t]*(.*)$/);
    need(match && !Object.hasOwn(row, match[1].toLowerCase()), 'B0_FACTS_FIELD_DUPLICATE_OR_SYNTAX');
    key = match[1].toLowerCase(); row[key] = match[2];
  }
  flush();
  return result;
}
function uri(value) {
  need(typeof value === 'string' && value.length <= 512 && !/[\x00-\x20\x7f$`\\]/.test(value), 'B0_FACTS_URI_REFUSED');
  let parsed; try { parsed = new URL(value); } catch (_) { need(false, 'B0_FACTS_URI_REFUSED'); }
  need(['http:', 'https:'].includes(parsed.protocol) && !parsed.username && !parsed.password && !parsed.search && !parsed.hash &&
    !parsed.port && /^[A-Za-z0-9.-]+$/.test(parsed.hostname) && /^[A-Za-z0-9/_.-]+$/.test(parsed.pathname), 'B0_FACTS_URI_REFUSED');
  return value;
}
function sourceRecord(row, sourcePath = null) {
  const permitted = new Set(['types', 'uris', 'suites', 'components', 'architectures', 'signed-by', 'enabled']);
  need(Object.keys(row).every(key => permitted.has(key)), 'B0_FACTS_SOURCE_FIELD_UNSUPPORTED');
  need(['types', 'uris', 'suites', 'components', 'signed-by'].every(key => row[key]), 'B0_FACTS_SOURCE_REQUIRED');
  const split = key => row[key].trim().split(/\s+/);
  const types = split('types'), uris = split('uris').map(uri), suites = split('suites'), components = split('components');
  need(types.every(v => v === 'deb' || v === 'deb-src') && suites.every(v => /^[a-z][a-z0-9-]{0,31}$/.test(v)) &&
    components.every(v => /^[a-z][a-z0-9-]{0,31}$/.test(v)), 'B0_FACTS_SOURCE_VALUE');
  if (row['signed-by'] === '/etc/apt/keyrings/nodesource.gpg') {
    need(Object.values(row).every(value => typeof value === 'string' && !/[\x00-\x1f\x7f-\x9f]/.test(value)) &&
      sourcePath === '/etc/apt/sources.list.d/nodesource.list' &&
      types.length === 1 && types[0] === 'deb' &&
      uris.length === 1 && uris[0] === 'https://deb.nodesource.com/node_26.x' &&
      suites.length === 1 && suites[0] === 'nodistro' &&
      components.length === 1 && components[0] === 'main' &&
      !Object.hasOwn(row, 'architectures') &&
      (!Object.hasOwn(row, 'enabled') || row.enabled === 'yes'), 'B0_FACTS_SIGNED_BY_UNSUPPORTED');
    // Recognize a declared public reference only. Never resolve/read this key.
    return {types, uris, suites, components, architectures: null,
      signed_by: row['signed-by'], enabled: 'yes', repository_authorized: false,
      reference_status: 'candidate_not_authorized',
      classification: 'recognized_candidate_reference_not_authorized', key_material_inspected: false};
  }
  need(row['signed-by'] === KEYRING, 'B0_FACTS_SIGNED_BY_UNSUPPORTED');
  const architectures = row.architectures ? split('architectures') : null;
  need(!architectures || architectures.every(v => /^[a-z0-9][a-z0-9-]{0,31}$/.test(v)), 'B0_FACTS_SOURCE_ARCH');
  need(!row.enabled || ['yes', 'no'].includes(row.enabled), 'B0_FACTS_SOURCE_ENABLED');
  return {types, uris, suites, components, architectures, signed_by: KEYRING, enabled: row.enabled || 'yes', repository_authorized: false};
}
function sources(data, kind, sourcePath = null) {
  if (kind === 'sources') return deb822(data, 4096, 256 * 1024, 64).map(row => sourceRecord(row, sourcePath));
  const records = [];
  for (const raw of lines(data, 4096)) {
    const line = raw.replace(/\s+#.*$/, '').trim(); if (!line || line.startsWith('#')) continue;
    const match = line.match(/^(deb(?:-src)?)\s+(?:\[([^\]]+)\]\s+)?(\S+)\s+(\S+)\s+(.+)$/);
    need(match, 'B0_FACTS_LIST_SYNTAX');
    const options = Object.create(null);
    for (const token of (match[2] || '').split(/\s+/).filter(Boolean)) {
      const pair = token.match(/^(arch|signed-by)=(\S+)$/);
      need(pair && !Object.hasOwn(options, pair[1]), 'B0_FACTS_LIST_OPTIONS_UNSUPPORTED'); options[pair[1]] = pair[2];
    }
    records.push(sourceRecord({types: match[1], uris: match[3], suites: match[4], components: match[5],
      'signed-by': options['signed-by'], ...(options.arch ? {architectures: options.arch.replaceAll(',', ' ')} : {})}, sourcePath));
  }
  return records;
}
function packages(data) {
  const records = deb822(data), result = [], seen = new Set();
  need(records.length <= 2048, 'B0_FACTS_PACKAGE_COUNT');
  const keys = ['package', 'version', 'architecture', 'multi-arch', 'status', 'source', 'depends', 'pre-depends', 'provides'];
  for (const row of records) {
    need(/^[a-z0-9][a-z0-9+.-]{0,127}$/.test(row.package || '') && /^[A-Za-z0-9.+:~_-]{1,128}$/.test(row.version || '') &&
      /^[a-z0-9][a-z0-9-]{0,31}$/.test(row.architecture || ''), 'B0_FACTS_PACKAGE_IDENTITY');
    const id = row.package + ':' + row.architecture; need(!seen.has(id), 'B0_FACTS_PACKAGE_DUPLICATE'); seen.add(id);
    const projected = Object.create(null);
    for (const key of keys) {
      const value = row[key];
      if (value !== undefined) need(/^[A-Za-z0-9 +:().<>=|,~_\[\]!*?-]{1,8192}$/.test(value), 'B0_FACTS_PACKAGE_FIELD');
      projected[key] = value === undefined ? null : value;
    }
    result.push(projected);
  }
  encodeBounded(result, 512 * 1024);
  return result;
}
function encodeBounded(value, maximum = LIMIT) {
  let bytes = 0, nodes = 0; const chunks = [];
  function append(piece) { bytes += Buffer.byteLength(piece); need(bytes <= maximum, 'B0_FACTS_OUTPUT_BUDGET'); chunks.push(piece); }
  function walk(item, depth) {
    need(++nodes <= 40000 && depth <= 16, 'B0_FACTS_OUTPUT_STRUCTURE');
    if (item === null || typeof item === 'boolean') return append(JSON.stringify(item));
    if (typeof item === 'number') { need(Number.isSafeInteger(item), 'B0_FACTS_OUTPUT_NUMBER'); return append(String(item)); }
    if (typeof item === 'string') { need(Buffer.byteLength(item) <= 8192, 'B0_FACTS_OUTPUT_STRING'); return append(JSON.stringify(item)); }
    if (Array.isArray(item)) { append('['); item.forEach((v, i) => { if (i) append(','); walk(v, depth + 1); }); return append(']'); }
    need(item && [Object.prototype, null].includes(Object.getPrototypeOf(item)), 'B0_FACTS_OUTPUT_TYPE');
    append('{'); Object.entries(item).forEach(([key, v], i) => { need(key.length <= 128, 'B0_FACTS_OUTPUT_KEY'); if (i) append(','); append(JSON.stringify(key)); append(':'); walk(v, depth + 1); }); append('}');
  }
  walk(value, 0); append('\n'); return chunks.join('');
}
function collect(io = fs) {
  const r = reader(io), inventory = [], os = [];
  for (const file of OS_PATHS) { const item = r.read(file, 65536); inventory.push(item.fact); if (item.data) os.push({path: file, fields: osFacts(item.data)}); }
  need(os.length > 0 && os.every(row => row.fields.ID === 'ubuntu'), 'B0_FACTS_OS_PROFILE_REFUSED');
  const sourcePaths = ['/etc/apt/sources.list', ...r.directory(SOURCE_DIR, 32, name => /^[A-Za-z0-9][A-Za-z0-9_.-]{0,120}\.(list|sources)$/.test(name)).entries];
  let sourceBytes = 0; const repositories = [];
  for (const file of sourcePaths) {
    const item = r.read(file, 65536); inventory.push(item.fact);
    if (!item.data) continue;
    sourceBytes += item.data.length; need(sourceBytes <= 256 * 1024, 'B0_FACTS_SOURCES_TOTAL');
    const parsed = sources(item.data, file.endsWith('.sources') ? 'sources' : 'list', file);
    if (parsed.some(record => record.reference_status === 'candidate_not_authorized'))
      need(item.fact.chain.length === 0 && item.fact.resolved_path === file, 'B0_FACTS_CANDIDATE_SOURCE_ALIAS_REFUSED');
    need(repositories.length + parsed.length <= 64, 'B0_FACTS_SOURCE_COUNT');
    repositories.push(...parsed.map(record => ({path: file, ...record})));
  }
  need(repositories.length > 0 && repositories.length <= 64 && repositories.reduce((n, row) => n + row.uris.length + row.suites.length + row.components.length, 0) <= 128, 'B0_FACTS_SOURCE_COUNT');
  const keyring = r.read(KEYRING, 65536, false); need(keyring.fact.present, 'B0_FACTS_KEYRING_MISSING'); inventory.push(keyring.fact);
  const trust = r.directory(TRUST_DIR, 32, name => TRUST_FILES.includes(name));
  const trustFacts = [];
  for (const file of ['/etc/apt/trusted.gpg', ...trust.entries]) { const item = r.read(file, 65536, false); inventory.push(item.fact); trustFacts.push(item.fact); }
  const status = r.read('/var/lib/dpkg/status', 2 * 1024**2); need(status.data, 'B0_FACTS_STATUS_MISSING'); inventory.push(status.fact);
  const installed = packages(status.data);
  const architectures = r.read('/var/lib/dpkg/arch', 4096); inventory.push(architectures.fact);
  const archNames = architectures.data ? [...lines(architectures.data, 128)].filter(Boolean) : null;
  need(!archNames || archNames.every(v => /^[a-z0-9][a-z0-9-]{0,31}$/.test(v)), 'B0_FACTS_ARCH_FILE');
  for (const file of [...TOOLS, ...NSS]) inventory.push(r.read(file, 8 * 1024**2, false).fact);
  return {schema: 'pamolive.b0-d0-public-facts/1', phase: 'public_file_inventory_only', code: 'B0_FACTS_PUBLIC_INVENTORY_READY', ok: true,
    os, repositories, keyring: {path: KEYRING, sha256: keyring.fact.sha256, primary_fingerprints: null, subkey_fingerprints: null, certificate_bindings_verified: false},
    global_trust_inventory: trustFacts, packages: installed, architecture_file_names: archNames,
    nss_package_records: Object.fromEntries(['libnss3', 'libnspr4', 'libnss3-tools'].map(name => [name, installed.filter(row => row.package === name)])),
    files: inventory, hashed_bytes: r.total(), truncation: false, stage0_passed: false, certutil_functional: null, nss_empty: null,
    Release_signatures_verified: false, archives_verified: false, dynamic_library_selection_verified: false, TLS_observed: false,
    sandbox_observed: false, CDP_observed: false, authority: false, build_verified: false, attestation_verified: false, release_qualified: false};
}
function main() {
  let result;
  try {
    const input = '/inputs/facts-pins.json', initial = fs.lstatSync(input, {bigint: true});
    need(initial.isFile() && initial.nlink === 1n && initial.size > 0n && initial.size <= 8192n, 'B0_FACTS_PINS_FILE_REFUSED');
    const fd = fs.openSync(input, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
    let raw;
    try {
      const opened = fs.fstatSync(fd, {bigint: true});
      need(opened.isFile() && same(initial, opened), 'B0_FACTS_PINS_FILE_REFUSED');
      const buffer = Buffer.alloc(8193); let count = 0;
      while (count < buffer.length) { const got = fs.readSync(fd, buffer, count, buffer.length - count, null); if (!got) break; count += got; }
      need(count === Number(opened.size) && count <= 8192 && same(opened, fs.fstatSync(fd, {bigint: true})), 'B0_FACTS_PINS_FILE_REFUSED');
      raw = buffer.subarray(0, count);
    } finally { fs.closeSync(fd); }
    need(raw.length <= 8192 && sha(raw) === process.env.B0_PINS_SHA256, 'B0_FACTS_PINS_CHANGED');
    const pins = JSON.parse(raw); // Host has already strict/schema/hash-checked this exact buffer.
    need(pins.schema === 'pamolive.b0-d0-pins/1' && pins.image === IMAGE && pins.image_config === CONFIG && pins.authority === false &&
      pins.node_entrypoint === '/usr/bin/node' && pins.node_min_major === 20 && pins.max_output_bytes === LIMIT, 'B0_FACTS_PINS_REFUSED');
    need(process.platform === 'linux' && process.arch === 'x64' && process.getuid() > 0 && process.getgid() > 0 && Number(process.versions.node.split('.')[0]) >= 20, 'B0_FACTS_RUNTIME_PROFILE_REFUSED');
    result = collect(); result.nodeVersion = process.version;
  } catch (error) {
    result = {schema: 'pamolive.b0-d0-public-facts/1', phase: 'public_file_inventory_only', ok: false,
      code: typeof error.code === 'string' && /^B0_FACTS_[A-Z0-9_]+$/.test(error.code) ? error.code : 'B0_FACTS_REFUSED',
      stage0_passed: false, primary_fingerprints: null, subkey_fingerprints: null, authority: false, release_qualified: false};
  }
  let encoded;
  try { encoded = encodeBounded(result); }
  catch (_) { result = {schema: 'pamolive.b0-d0-public-facts/1', phase: 'public_file_inventory_only', ok: false, code: 'B0_FACTS_OUTPUT_BUDGET', stage0_passed: false, authority: false}; encoded = encodeBounded(result); }
  fs.writeFileSync('/evidence/facts.json', encoded, {flag: 'wx', mode: 0o600});
  process.stdout.write(JSON.stringify({code: result.code, ok: result.ok, stage0_passed: false}) + '\n');
  process.exitCode = result.ok ? 0 : 42;
}
module.exports = {reader, osFacts, sources, sourceRecord, packages, encodeBounded, collect, allowed, uri, IMAGE, CONFIG, KEYRING, LIMIT};
if (require.main === module) main();
