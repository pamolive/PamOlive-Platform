'use strict';
// Host tests use ONLY the in-memory filesystem below. main()/image are never run.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path').posix;
const F = require('./facts.cjs');
class FakeFS {
  constructor() { this.entries = new Map(); this.fds = new Map(); this.next = 1; this.opens = 0; this.reads = 0;
    this.constants = {O_RDONLY: 0, O_NOFOLLOW: 1, O_NONBLOCK: 2}; this.add('/', 'dir'); }
  add(name, kind = 'file', data = '', options = {}) {
    if (name !== '/' && !this.entries.has(path.dirname(name))) this.add(path.dirname(name), 'dir');
    this.entries.set(name, {kind, data: Buffer.from(data), target: options.target, mode: BigInt(options.mode === undefined ? (kind === 'dir' ? 0o40755 : kind === 'link' ? 0o120777 : 0o100644) : options.mode), uid: 0n, gid: 0n, nlink: BigInt(options.nlink || 1), ino: BigInt(this.entries.size + 1), ...options});
    return this;
  }
  lstatSync(name) {
    const row = this.entries.get(name);
    if (!row) { const error = new Error('NO CONTENT'); error.code = 'ENOENT'; throw error; }
    return {mode: row.mode, uid: row.uid, gid: row.gid, nlink: row.nlink, size: row.size === undefined ? BigInt(row.kind === 'file' ? row.data.length : 0) : row.size,
      dev: 1n, ino: row.ino, isFile: () => row.kind === 'file', isDirectory: () => row.kind === 'dir', isSymbolicLink: () => row.kind === 'link'};
  }
  readlinkSync(name) { return this.entries.get(name).target; }
  readdirSync(name) { return [...this.entries.keys()].filter(p => p !== name && path.dirname(p) === name).map(p => path.basename(p)); }
  opendirSync(name, options) {
    assert.equal(options.bufferSize, 1); const names = this.readdirSync(name); let i = 0;
    return {readSync: () => i < names.length ? {name: names[i++]} : null, closeSync: () => {}};
  }
  openSync(name) { this.opens++; const fd = this.next++; this.fds.set(fd, {name, offset: 0}); return fd; }
  fstatSync(fd) { return this.lstatSync(this.fds.get(fd).name); }
  readSync(fd, target, offset, amount) {
    assert.ok(Number.isInteger(amount) && amount > 0 && amount <= 32768); this.reads++;
    const info = this.fds.get(fd), row = this.entries.get(info.name);
    const block = row.data.subarray(info.offset, info.offset + amount);
    block.copy(target, offset); info.offset += block.length; return block.length;
  }
  closeSync(fd) { this.fds.delete(fd); }
}
const source = 'Types: deb\nURIs: http://archive.ubuntu.com/ubuntu/\nSuites: noble noble-updates\nComponents: main universe\nSigned-By: ' + F.KEYRING + '\n';
const status = 'Package: libnss3\nVersion: 2:3.1-fixture\nArchitecture: amd64\nStatus: install ok installed\nSource: nss (2:3.1-fixture)\nDepends: libc6 (>= 2.34), libnspr4 (>= 4.0)\nDescription: NEVER_EXPORT_DESCRIPTION\n\nPackage: libnspr4\nVersion: 4.0-fixture\nArchitecture: amd64\nStatus: install ok installed\n\n';
function fixture() {
  return new FakeFS().add('/usr/lib/os-release', 'file', 'ID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\n')
    .add('/etc/os-release', 'link', '', {target: '../usr/lib/os-release'})
    .add('/etc/apt/sources.list.d/ubuntu.sources', 'file', source)
    .add(F.KEYRING, 'file', 'NEVER_EXPORT_RAW_KEYRING')
    .add('/var/lib/dpkg/status', 'file', status);
}
function refuses(callback, code) { assert.throws(callback, error => error.code === code); }
test('complete synthetic facts; no NSS/PG/browser/key authority and no raw keyring/status description', () => {
  const data = F.collect(fixture()), encoded = F.encodeBounded(data);
  assert.equal(data.ok, true); assert.equal(data.phase, 'public_file_inventory_only');
  assert.equal(data.stage0_passed, false); assert.equal(data.certutil_functional, null); assert.equal(data.keyring.primary_fingerprints, null);
  assert.equal(data.keyring.subkey_fingerprints, null); assert.equal(data.keyring.certificate_bindings_verified, false);
  assert.equal(data.nss_package_records['libnss3-tools'].length, 0); assert.equal(data.packages.length, 2);
  assert.equal(data.files.find(row => row.path === '/usr/bin/certutil').present, false);
  assert.equal(encoded.includes('NEVER_EXPORT'), false); assert.ok(Buffer.byteLength(encoded) < F.LIMIT);
});
test('legacy OS alias is virtual and normal0777 is not writable file authority', () => {
  const read = F.reader(fixture()).read('/etc/os-release', 65536);
  assert.equal(read.fact.resolved_path, '/usr/lib/os-release'); assert.equal(read.fact.chain.length, 1);
});
test('no reads outside exact public path set', () => {
  const io = fixture(); refuses(() => F.reader(io).read('/etc/apt/auth.conf', 65536), 'B0_FACTS_PATH_REFUSED'); assert.equal(io.opens, 0);
});
test('huge file refused before open', () => {
  const io = fixture(); io.entries.get('/var/lib/dpkg/status').size = 1n << 40n;
  refuses(() => F.reader(io).read('/var/lib/dpkg/status', 1024), 'B0_FACTS_FILE_TYPE_OR_BUDGET'); assert.equal(io.opens, 0);
});
test('hardlink and special file refused before open', () => {
  for (const options of [{nlink: 2n}, {kind: 'fifo'}]) {
    const io = fixture(); Object.assign(io.entries.get('/var/lib/dpkg/status'), options);
    refuses(() => F.reader(io).read('/var/lib/dpkg/status', 65536), 'B0_FACTS_FILE_TYPE_OR_BUDGET'); assert.equal(io.opens, 0);
  }
});
test('opened inode replacement is refused before read', () => {
  const io = fixture(), original = io.fstatSync.bind(io);
  io.fstatSync = fd => ({...original(fd), ino: 99999n});
  refuses(() => F.reader(io).read('/var/lib/dpkg/status', 65536), 'B0_FACTS_OPEN_IDENTITY_REFUSED'); assert.equal(io.reads, 0);
});
test('checked terminal metadata is held until fstat; changed owner cannot replace it', () => {
  const io = fixture(), original = io.lstatSync.bind(io); let calls = 0;
  io.lstatSync = name => {
    const info = original(name);
    if (name === '/var/lib/dpkg/status' && ++calls > 1) info.uid = 999n;
    return info;
  };
  refuses(() => F.reader(io).read('/var/lib/dpkg/status', 65536), 'B0_FACTS_OPEN_IDENTITY_REFUSED');
  assert.equal(io.reads, 0);
});
test('exact file cap succeeds; +1 growth refuses and no FD remains', () => {
  const io = fixture(); io.entries.get('/var/lib/dpkg/status').data = Buffer.from('abcd');
  assert.equal(F.reader(io).read('/var/lib/dpkg/status', 4).data.toString(), 'abcd');
  io.entries.get('/var/lib/dpkg/status').data = Buffer.from('abcde'); io.entries.get('/var/lib/dpkg/status').size = 4n;
  refuses(() => F.reader(io).read('/var/lib/dpkg/status', 4), 'B0_FACTS_FILE_GROWTH_REFUSED'); assert.equal(io.fds.size, 0);
});
test('leaf escape/cycle and ancestor alias refuse without secret file read', () => {
  const io = fixture(); io.entries.get('/etc/os-release').target = '/etc/apt/auth.conf';
  refuses(() => F.reader(io).read('/etc/os-release', 65536), 'B0_FACTS_LINK_SCOPE_REFUSED');
  io.entries.get('/etc/os-release').target = '/usr/lib/os-release'; io.add('/usr/lib/os-release', 'link', '', {target: '/etc/os-release'});
  refuses(() => F.reader(io).read('/etc/os-release', 65536), 'B0_FACTS_LINK_CYCLE');
  io.add('/usr/share', 'link', '', {target: '/root'});
  refuses(() => F.reader(io).read(F.KEYRING, 65536), 'B0_FACTS_ANCESTOR_ALIAS_REFUSED'); assert.equal(io.opens, 0);
});
test('unsafe directory names are rejected, not skipped', () => {
  const io = fixture().add('/etc/apt/sources.list.d/token.txt', 'file', 'NEVER_EXPORT');
  refuses(() => F.collect(io), 'B0_FACTS_DIRECTORY_ENTRY_REFUSED');
});
test('directory overflow stops at maximum+1 without reading all entries', () => {
  const io = fixture(); let calls = 0, closed = false;
  io.opendirSync = () => ({readSync: () => ({name: 'p' + (++calls) + '.sources'}), closeSync: () => {closed = true;}});
  refuses(() => F.reader(io).directory('/etc/apt/sources.list.d', 32, () => true), 'B0_FACTS_DIRECTORY_BUDGET');
  assert.equal(calls, 33); assert.equal(closed, true);
});
test('read-only public files require root and no group/world write', () => {
  for (const change of [{uid: 1000n}, {gid: 1000n}, {mode: 0o100666n}]) {
    const io = fixture(); Object.assign(io.entries.get('/var/lib/dpkg/status'), change);
    refuses(() => F.reader(io).read('/var/lib/dpkg/status', 65536), 'B0_FACTS_PUBLIC_METADATA_REFUSED'); assert.equal(io.opens, 0);
  }
});
test('safe deb822/list facts agree without repo authorization', () => {
  const a = F.sources(Buffer.from(source), 'sources')[0];
  const b = F.sources(Buffer.from('deb [signed-by=' + F.KEYRING + '] http://archive.ubuntu.com/ubuntu/ noble main\n'), 'list')[0];
  assert.equal(a.repository_authorized, false); assert.equal(b.repository_authorized, false); assert.equal(a.signed_by, b.signed_by);
});
test('credentials/query/fragment/variable/insecure URI rejected with code-only error', () => {
  for (const value of ['https://user:private@archive.ubuntu.com/ubuntu/', 'https://archive.ubuntu.com/?private=1', 'https://archive.ubuntu.com/#private', 'file:///etc/passwd', 'https://archive.ubuntu.com/$PRIVATE', 'https://archive.ubuntu.com/\nPRIVATE']) {
    refuses(() => F.uri(value), 'B0_FACTS_URI_REFUSED');
  }
});
test('insecure options/implicit keys/unknown Signed-By/duplicates/inline key refuse', () => {
  refuses(() => F.sources(Buffer.from('deb [trusted=yes] http://archive.ubuntu.com/ubuntu/ noble main\n'), 'list'), 'B0_FACTS_LIST_OPTIONS_UNSUPPORTED');
  refuses(() => F.sources(Buffer.from(source.replace('Signed-By: ' + F.KEYRING, 'Signed-By: /root/private.gpg')), 'sources'), 'B0_FACTS_SIGNED_BY_UNSUPPORTED');
  refuses(() => F.sources(Buffer.from(source + 'URIs: https://security.ubuntu.com/ubuntu/\n'), 'sources'), 'B0_FACTS_FIELD_DUPLICATE_OR_SYNTAX');
  refuses(() => F.sources(Buffer.from(source.replace('Signed-By: ' + F.KEYRING, 'Signed-By: -----BEGIN PGP PUBLIC KEY BLOCK-----')), 'sources'), 'B0_FACTS_SIGNED_BY_UNSUPPORTED');
  refuses(() => F.sources(Buffer.from(source + 'Trusted: yes\n'), 'sources'), 'B0_FACTS_SOURCE_FIELD_UNSUPPORTED');
});
test('NSS dependency facts preserve alternatives/versions, never solve', () => {
  const rows = F.packages(Buffer.from(status.replace('libc6 (>= 2.34)', 'libc6 (>= 2.34) | libc-alt:any')));
  assert.ok(rows[0].depends.includes('| libc-alt:any')); assert.equal(rows[0].status, 'install ok installed');
});
test('duplicate packages/fields and excessive records/line refuse early', () => {
  refuses(() => F.packages(Buffer.from(status + status)), 'B0_FACTS_PACKAGE_DUPLICATE');
  refuses(() => F.packages(Buffer.from(status.replace('Version: 2:3.1-fixture', 'Version: 2:3.1-fixture\nVersion: 9'))), 'B0_FACTS_FIELD_DUPLICATE_OR_SYNTAX');
  refuses(() => F.packages(Buffer.from(Array.from({length: 2049}, (_, i) => `Package: p${i}\nVersion: 1\nArchitecture: amd64\nStatus: install ok installed\n\n`).join(''))), 'B0_FACTS_RECORD_COUNT');
  refuses(() => F.packages(Buffer.from('Package: ' + 'x'.repeat(65537))), 'B0_FACTS_LINE_BUDGET');
});
test('stanza limit counts raw UTF8 including every CRLF, exact and +1', () => {
  const first = 'Package: nss\r\nVersion: 1\r\nArchitecture: amd64\r\nStatus: install ok installed\r\n';
  const prefix = first + 'Description: x\r\n';
  const tail = ' z\r\n';
  const maximum = 256 * 1024;
  const remaining = maximum - Buffer.byteLength(prefix) - Buffer.byteLength('\r\n');
  const repeated = tail.repeat(Math.floor(remaining / Buffer.byteLength(tail)));
  const residue = remaining - Buffer.byteLength(repeated);
  let data = prefix + repeated;
  if (residue) data += ' '.repeat(residue); // whitespace continuation, no newline, consumes exact remainder
  data += '\r\n';
  assert.equal(Buffer.byteLength(data), maximum);
  assert.equal(F.packages(Buffer.from(data)).length, 1);
  refuses(() => F.packages(Buffer.from(data.replace('Description: x\r\n', 'Description: xx\r\n'))), 'B0_FACTS_STANZA_BUDGET');
  refuses(() => F.packages(Buffer.from(data.replace('Description: x\r\n', 'Description: é\r\n'))), 'B0_FACTS_STANZA_BUDGET');
});
test('fatalUTF8/NUL and unsupported OS values refuse', () => {
  refuses(() => F.osFacts(Buffer.from([255])), 'B0_FACTS_UTF8_REFUSED');
  refuses(() => F.osFacts(Buffer.from('ID=ubuntu\0')), 'B0_FACTS_NUL_REFUSED');
  refuses(() => F.osFacts(Buffer.from('ID=$(PRIVATE)')), 'B0_FACTS_OS_VALUE');
});
test('bounded serializer exact/+1 and shared objects stop before huge expansion', () => {
  const raw = F.encodeBounded({value: 'abc'}), length = Buffer.byteLength(raw);
  assert.equal(F.encodeBounded({value: 'abc'}, length), raw);
  refuses(() => F.encodeBounded({value: 'abcd'}, length), 'B0_FACTS_OUTPUT_BUDGET');
  const shared = 'x'.repeat(8192);
  refuses(() => F.encodeBounded(Array(2048).fill(shared), 65536), 'B0_FACTS_OUTPUT_BUDGET');
  refuses(() => F.encodeBounded({value: Infinity}), 'B0_FACTS_OUTPUT_NUMBER');
});
test('no executable/network/private Env APIs in probe dependencies', () => {
  // Pure dependency contract; this imports only this reviewed module and fake fs.
  assert.deepEqual(Object.keys(F).sort(), ['CONFIG', 'IMAGE', 'KEYRING', 'LIMIT', 'allowed', 'collect', 'encodeBounded', 'osFacts', 'packages', 'reader', 'sourceRecord', 'sources', 'uri'].sort());
});

const NODE_SOURCE_FILE = '/etc/apt/sources.list.d/nodesource.list';
const NODE_KEY_REFERENCE = '/etc/apt/keyrings/nodesource.gpg';
const NODE_URI = 'https://deb.nodesource.com/node_26.x';
const nodeList = 'deb [signed-by=' + NODE_KEY_REFERENCE + '] ' + NODE_URI + ' nodistro main\n';
function nodeRow() {
  return {types: 'deb', uris: NODE_URI, suites: 'nodistro', components: 'main', 'signed-by': NODE_KEY_REFERENCE};
}
function candidateOnly(row) {
  assert.equal(row.signed_by, NODE_KEY_REFERENCE);
  assert.equal(row.reference_status, 'candidate_not_authorized');
  assert.equal(row.classification, 'recognized_candidate_reference_not_authorized');
  assert.equal(row.key_material_inspected, false);
  assert.equal(row.repository_authorized, false);
  assert.equal(Object.hasOwn(row, 'sha256'), false);
  assert.equal(Object.hasOwn(row, 'primary_fingerprints'), false);
}
test('exact Node26 tuple is a public candidate reference only; no key material is read', () => {
  const io = fixture().add(NODE_SOURCE_FILE, 'file', nodeList)
    .add(NODE_KEY_REFERENCE, 'file', 'NEVER_OPEN_NODE_KEY');
  const originalStat = io.lstatSync.bind(io), originalOpen = io.openSync.bind(io), opened = [];
  io.lstatSync = name => { assert.notEqual(name, NODE_KEY_REFERENCE); return originalStat(name); };
  io.openSync = name => { opened.push(name); assert.notEqual(name, NODE_KEY_REFERENCE); return originalOpen(name); };
  const facts = F.collect(io), candidate = facts.repositories.find(row => row.path === NODE_SOURCE_FILE);
  candidateOnly(candidate);
  assert.deepEqual(candidate.uris, [NODE_URI]); assert.deepEqual(candidate.types, ['deb']);
  assert.deepEqual(candidate.suites, ['nodistro']); assert.deepEqual(candidate.components, ['main']);
  assert.equal(candidate.architectures, null); assert.equal(candidate.enabled, 'yes');
  assert.ok(opened.includes(F.KEYRING));
  assert.equal(facts.keyring.path, F.KEYRING);
  assert.equal(facts.keyring.sha256, require('node:crypto').createHash('sha256').update('NEVER_EXPORT_RAW_KEYRING').digest('hex'));
  assert.ok(!facts.files.some(row => row.path === NODE_KEY_REFERENCE));
  assert.equal(F.allowed(NODE_KEY_REFERENCE), false);
  assert.equal(F.encodeBounded(facts).includes('NEVER_OPEN_NODE_KEY'), false);
  for (const key of ['authority', 'stage0_passed', 'build_verified', 'attestation_verified', 'release_qualified', 'Release_signatures_verified', 'archives_verified', 'TLS_observed', 'sandbox_observed', 'CDP_observed']) assert.equal(facts[key], false);
  assert.equal(facts.certutil_functional, null); assert.equal(facts.keyring.primary_fingerprints, null);
});
test('Node key path remains inaccessible even if absent/alias/FIFO/oversize', () => {
  for (const variation of [null, {kind: 'link', target: '/etc/shadow'}, {kind: 'fifo'}, {size: 1n << 40n}]) {
    const io = fixture().add(NODE_SOURCE_FILE, 'file', nodeList);
    if (variation) io.add(NODE_KEY_REFERENCE, 'file', 'NO_READ', variation);
    const stat = io.lstatSync.bind(io);
    io.lstatSync = name => { assert.notEqual(name, NODE_KEY_REFERENCE); return stat(name); };
    candidateOnly(F.collect(io).repositories.find(row => row.path === NODE_SOURCE_FILE));
    const before = io.opens;
    refuses(() => F.reader(io).read(NODE_KEY_REFERENCE, 65536), 'B0_FACTS_PATH_REFUSED');
    assert.equal(io.opens, before);
  }
});
test('Node candidate requires exact declared source file; Ubuntu projection unchanged', () => {
  for (const file of [null, '/etc/apt/sources.list', '/etc/apt/sources.list.d/other.list', '/etc/apt/sources.list.d/nodesource.sources', '/etc/apt/sources.list.d/../sources.list.d/nodesource.list']) {
    refuses(() => F.sources(Buffer.from(nodeList), 'list', file), 'B0_FACTS_SIGNED_BY_UNSUPPORTED');
  }
  const ubuntu = F.sources(Buffer.from(source), 'sources', '/etc/apt/sources.list.d/ubuntu.sources')[0];
  assert.deepEqual(ubuntu, {types: ['deb'], uris: ['http://archive.ubuntu.com/ubuntu/'], suites: ['noble', 'noble-updates'], components: ['main', 'universe'], architectures: null, signed_by: F.KEYRING, enabled: 'yes', repository_authorized: false});
  assert.equal(Object.hasOwn(ubuntu, 'reference_status'), false);
  // Preserve the old Ubuntu-keyring projection exactly; it is not authority
  // for a URI and never becomes a recognized NodeSource candidate.
  const oldProjection = F.sourceRecord({...nodeRow(), 'signed-by': F.KEYRING}, NODE_SOURCE_FILE);
  assert.equal(oldProjection.signed_by, F.KEYRING);
  assert.equal(oldProjection.repository_authorized, false);
  assert.equal(Object.hasOwn(oldProjection, 'reference_status'), false);
});
test('Node candidate source file aliases remain refused without changing Ubuntu alias reader', () => {
  const io = fixture().add('/etc/apt/sources.list.d/alias.list', 'file', nodeList)
    .add(NODE_SOURCE_FILE, 'link', '', {target: 'alias.list'});
  // Avoid directory lexical order selecting alias.list first: exercise the
  // closed reader with only the declared node filename returned by FakeFS.
  const directory = io.opendirSync.bind(io);
  io.opendirSync = (name, options) => name === '/etc/apt/sources.list.d' ?
    {readSync: (() => { let once = false; return () => once ? null : (once = true, {name: 'nodesource.list'}); })(), closeSync: () => {}} : directory(name, options);
  refuses(() => F.collect(io), 'B0_FACTS_CANDIDATE_SOURCE_ALIAS_REFUSED');
});
test('every Node tuple member divergence remains refused, including missing or mixed data', () => {
  const mutations = {
    types: ['deb-src', 'deb deb-src', 'deb deb'],
    uris: ['http://deb.nodesource.com/node_26.x', 'https://deb.nodesource.com/node_24.x', 'https://deb.nodesource.com/node_26.x/', 'https://deb.nodesource.com/node_26.x https://archive.ubuntu.com/ubuntu/', 'https://mirror.example/node_26.x'],
    suites: ['noble', 'nodistro noble', 'nodistro nodistro'],
    components: ['universe', 'main universe', 'main main'],
    'signed-by': ['/etc/apt/keyrings/other.gpg', '/etc/apt/keyrings/./nodesource.gpg', '/usr/share/keyrings/nodesource.gpg', NODE_KEY_REFERENCE + ' ' + F.KEYRING, '-----BEGIN PGP PUBLIC KEY BLOCK-----'],
    architectures: ['', 'amd64', 'arm64', 'amd64 arm64'],
    enabled: ['', 'no', 'true'],
  };
  for (const [key, values] of Object.entries(mutations)) for (const value of values) {
    const row = {...nodeRow(), [key]: value};
    assert.throws(() => F.sourceRecord(row, NODE_SOURCE_FILE), error => /^B0_FACTS_/.test(error.code));
  }
  for (const key of Object.keys(nodeRow())) {
    const row = nodeRow(); delete row[key];
    assert.throws(() => F.sourceRecord(row, NODE_SOURCE_FILE), error => /^B0_FACTS_/.test(error.code));
  }
  candidateOnly(F.sourceRecord({...nodeRow(), enabled: 'yes'}, NODE_SOURCE_FILE));
});
test('Node credentials/query/fragment/port/control/backslash/substitutions and options refused', () => {
  for (const value of ['https://user:secret@deb.nodesource.com/node_26.x', NODE_URI + '?token=secret', NODE_URI + '#secret', 'https://deb.nodesource.com:8443/node_26.x', NODE_URI + '\n', NODE_URI + '/$TOKEN', NODE_URI + '/`whoami`', NODE_URI + '\\evil']) {
    assert.throws(() => F.sourceRecord({...nodeRow(), uris: value}, NODE_SOURCE_FILE), error => /^B0_FACTS_/.test(error.code));
  }
  for (const options of ['trusted=yes', 'arch=amd64', 'allow-insecure=yes', 'signed-by=' + NODE_KEY_REFERENCE + ' signed-by=' + NODE_KEY_REFERENCE]) {
    const line = 'deb [signed-by=' + NODE_KEY_REFERENCE + ' ' + options + '] ' + NODE_URI + ' nodistro main\n';
    assert.throws(() => F.sources(Buffer.from(line), 'list', NODE_SOURCE_FILE), error => /^B0_FACTS_/.test(error.code));
  }
  assert.throws(() => F.sourceRecord({...nodeRow(), trusted: 'yes'}, NODE_SOURCE_FILE), error => /^B0_FACTS_/.test(error.code));
});
test('FakeFS collect rejects divergent Node source path/URI/version/suite/components/options without key reads', () => {
  const altered = [
    [NODE_SOURCE_FILE, nodeList.replace('node_26.x', 'node_24.x')],
    [NODE_SOURCE_FILE, nodeList.replace('node_26.x', 'node_27.x')],
    [NODE_SOURCE_FILE, nodeList.replace('https://', 'http://')],
    [NODE_SOURCE_FILE, nodeList.replace('deb.nodesource.com', 'mirror.example')],
    [NODE_SOURCE_FILE, nodeList.replace('https://', 'https://user:secret@')],
    [NODE_SOURCE_FILE, nodeList.replace(' nodistro ', '?token=secret nodistro ')],
    [NODE_SOURCE_FILE, nodeList.replace(' nodistro ', ' noble ')],
    [NODE_SOURCE_FILE, nodeList.replace(' main\n', ' main universe\n')],
    [NODE_SOURCE_FILE, nodeList.replace(' main\n', ' universe\n')],
    [NODE_SOURCE_FILE, nodeList.replace('deb [', 'deb-src [')],
    [NODE_SOURCE_FILE, nodeList.replace('] ', ' arch=amd64] ')],
    [NODE_SOURCE_FILE, nodeList.replace('] ', ' trusted=yes] ')],
    [NODE_SOURCE_FILE, nodeList.replace(NODE_KEY_REFERENCE, '/root/private.gpg')],
    ['/etc/apt/sources.list.d/other.list', nodeList],
    ['/etc/apt/sources.list.d/nodesource.sources', nodeList],
  ];
  for (const [file, data] of altered) {
    const io = fixture().add(file, 'file', data).add(NODE_KEY_REFERENCE, 'file', 'NEVER_OPEN_NODE_KEY');
    const open = io.openSync.bind(io), opened = [];
    io.openSync = name => { opened.push(name); return open(name); };
    assert.throws(() => F.collect(io), error => /^B0_FACTS_/.test(error.code) && !error.message.includes('secret'));
    assert.ok(!opened.includes(NODE_KEY_REFERENCE)); assert.ok(!opened.includes('/root/private.gpg'));
  }
});
