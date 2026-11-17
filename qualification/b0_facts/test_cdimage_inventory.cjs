'use strict';
// All public-file data and metadata below are synthetic in-memory fixtures.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const path = require('node:path').posix;
const F = require('./facts.cjs');
const TRUST = '/etc/apt/trusted.gpg.d';
const CD = TRUST + '/ubuntu-keyring-2012-cdimage.gpg';
const OLD = ['ubuntu-keyring-2012-archive.gpg', 'ubuntu-keyring-2018-archive.gpg'];
const RAW = 'SYNTHETIC_CDIMAGE_BYTES_NOT_A_REAL_KEY_NEVER_EXPORT';
function sha(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
class FakeFS {
  constructor() { this.entries = new Map(); this.fds = new Map(); this.next = 1; this.opened = []; this.readNames = [];
    this.constants = {O_RDONLY: 0, O_NOFOLLOW: 1, O_NONBLOCK: 2}; this.add('/', 'dir'); }
  add(name, kind = 'file', data = '', options = {}) {
    if (name !== '/' && !this.entries.has(path.dirname(name))) this.add(path.dirname(name), 'dir');
    this.entries.set(name, {kind, data: Buffer.from(data), target: options.target,
      mode: BigInt(kind === 'dir' ? 0o40755 : kind === 'link' ? 0o120777 : 0o100644),
      uid: 0n, gid: 0n, nlink: 1n, ino: BigInt(this.entries.size + 1), ...options}); return this;
  }
  lstatSync(name) {
    const row = this.entries.get(name);
    if (!row) { const error = new Error('SYNTHETIC_ABSENT'); error.code = 'ENOENT'; throw error; }
    return {mode: row.mode, uid: row.uid, gid: row.gid, nlink: row.nlink,
      size: row.size === undefined ? BigInt(row.kind === 'file' ? row.data.length : 0) : row.size,
      dev: 1n, ino: row.ino, isFile: () => row.kind === 'file', isDirectory: () => row.kind === 'dir', isSymbolicLink: () => row.kind === 'link'};
  }
  readlinkSync(name) { return this.entries.get(name).target; }
  opendirSync(name, options) {
    assert.equal(options.bufferSize, 1);
    const names = [...this.entries.keys()].filter(p => p !== name && path.dirname(p) === name).map(p => path.basename(p)); let index = 0;
    return {readSync: () => index < names.length ? {name: names[index++]} : null, closeSync() {}};
  }
  openSync(name) { this.opened.push(name); const fd = this.next++; this.fds.set(fd, {name, offset: 0}); return fd; }
  fstatSync(fd) { return this.lstatSync(this.fds.get(fd).name); }
  readSync(fd, buffer, offset, amount) {
    assert.ok(Number.isInteger(amount) && amount > 0 && amount <= 32768);
    const state = this.fds.get(fd); this.readNames.push(state.name);
    const block = this.entries.get(state.name).data.subarray(state.offset, state.offset + amount);
    block.copy(buffer, offset); state.offset += block.length; return block.length;
  }
  closeSync(fd) { this.fds.delete(fd); }
}
function fixture() {
  const io = new FakeFS().add('/usr/lib/os-release', 'file', 'ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n')
    .add('/etc/os-release', 'link', '', {target: '../usr/lib/os-release'})
    .add('/etc/apt/sources.list.d/ubuntu.sources', 'file', 'Types: deb\nURIs: http://archive.ubuntu.com/ubuntu/\nSuites: noble\nComponents: main\nSigned-By: ' + F.KEYRING + '\n')
    .add(F.KEYRING, 'file', 'SYNTHETIC_ARCHIVE_BYTES_NEVER_EXPORT')
    .add('/var/lib/dpkg/status', 'file', 'Package: libnss3\nVersion: 1-fixture\nArchitecture: amd64\nStatus: install ok installed\n\n')
    .add(CD, 'file', RAW);
  for (const name of OLD) io.add(TRUST + '/' + name, 'file', 'SYNTHETIC_OLD_BYTES_NEVER_EXPORT');
  return io;
}
function refuses(callback, code) { assert.throws(callback, error => error.code === code); }
test('CDimage adds one hash-only public inventory fact; no raw bytes, fingerprints or repository authority', () => {
  const io = fixture(), facts = F.collect(io), encoded = F.encodeBounded(facts);
  assert.equal(facts.ok, true); assert.equal(facts.global_trust_inventory.filter(row => row.present).length, 3);
  const fact = facts.global_trust_inventory.find(row => row.path === CD);
  assert.equal(fact.sha256, sha(RAW)); assert.equal(fact.metadata.size, Buffer.byteLength(RAW));
  assert.equal(fact.metadata.uid, 0); assert.equal(fact.metadata.gid, 0); assert.equal(fact.metadata.mode, '0644');
  assert.equal(fact.resolved_path, CD); assert.deepEqual(fact.chain, []);
  assert.equal(Object.hasOwn(fact, 'data'), false); assert.equal(Object.hasOwn(fact, 'primary_fingerprints'), false);
  assert.equal(encoded.includes('NEVER_EXPORT'), false); assert.equal(facts.authority, false);
  assert.equal(facts.release_qualified, false); assert.equal(facts.stage0_passed, false);
  assert.equal(facts.Release_signatures_verified, false); assert.equal(facts.keyring.primary_fingerprints, null);
  assert.equal(facts.keyring.subkey_fingerprints, null); assert.equal(facts.keyring.certificate_bindings_verified, false);
  assert.equal(io.fds.size, 0);
  const read = F.reader(fixture()).read(CD, 65536, false);
  assert.equal(read.data, null); assert.equal(read.fact.sha256, sha(RAW));
});
test('the actual CI basename hash is only a 31-byte name observation, not key content', () => {
  const name = path.basename(CD); assert.equal(Buffer.byteLength(name), 31);
  assert.equal(sha(name), '7979360d56412de73e4e61b50bec991625ac44aba6bd9be5172dd97c43aee706');
  assert.notEqual(sha(RAW), sha(name));
});
test('other key names, CD suffix/case variants and unknown entries stay refused without their content being opened', () => {
  for (const name of ['other.gpg', 'ubuntu-keyring-2012-cdimage.gpg.extra', 'ubuntu-keyring-2012-CDIMAGE.gpg', 'ubuntu-keyring-2026-cdimage.gpg']) {
    const io = fixture().add(TRUST + '/' + name, 'file', 'SYNTHETIC_REJECTED_CONTENT_NEVER_EXPORT');
    let caught;
    assert.throws(() => F.collect(io), error => { caught = error; return error.code === 'B0_FACTS_DIRECTORY_ENTRY_REFUSED'; });
    assert.equal(caught.directory_entry_diagnostic.basename_sha256, sha(name));
    assert.equal(caught.directory_entry_diagnostic.directory_context, 'trusted_gpg_d');
    assert.equal(JSON.stringify(caught.directory_entry_diagnostic).includes(name), false);
    assert.equal(io.opened.includes(TRUST + '/' + name), false); assert.equal(io.fds.size, 0);
  }
});
test('CD aliases to another allowed FIXED file refuse before any open/hash while old aliases keep their existing behavior', () => {
  for (const target of [F.KEYRING, TRUST + '/' + OLD[0], TRUST + '/ubuntu-keyring-2018-archive.gpg']) {
    const io = fixture().add(CD, 'link', '', {target});
    refuses(() => F.reader(io).read(CD, 65536, false), 'B0_FACTS_CDIMAGE_ALIAS_REFUSED');
    assert.deepEqual(io.opened, []); assert.deepEqual(io.readNames, []);
  }
  const io = fixture().add(TRUST + '/' + OLD[0], 'link', '', {target: F.KEYRING});
  assert.equal(F.reader(io).read(TRUST + '/' + OLD[0], 65536, false).fact.resolved_path, F.KEYRING);
});
test('CD escape/cycle and trusted directory ancestor aliases retain their prior refusal', () => {
  for (const [target, code] of [['/etc/apt/auth.conf', 'B0_FACTS_LINK_SCOPE_REFUSED'], [CD, 'B0_FACTS_LINK_CYCLE']]) {
    const io = fixture().add(CD, 'link', '', {target});
    refuses(() => F.reader(io).read(CD, 65536, false), code); assert.deepEqual(io.opened, []);
  }
  const io = fixture().add(TRUST, 'link', '', {target: '/root'});
  refuses(() => F.collect(io), 'B0_FACTS_DIRECTORY_METADATA'); assert.equal(io.opened.includes(CD), false);
});
test('CD owner/group/write/type/hardlink/huge-file metadata is checked before opening', () => {
  for (const fields of [{uid: 1000n}, {gid: 1000n}, {mode: 0o100664n}, {mode: 0o100646n}, {kind: 'fifo'}, {kind: 'dir'}, {nlink: 2n}, {size: 65537n}, {size: 1n << 40n}]) {
    const io = fixture(); Object.assign(io.entries.get(CD), fields);
    assert.throws(() => F.reader(io).read(CD, 65536, false), error => /^B0_FACTS_/.test(error.code));
    assert.deepEqual(io.opened, []); assert.deepEqual(io.readNames, []); assert.equal(io.fds.size, 0);
  }
});
test('CD exact64KiB hashes only, plus-one growth refuses and closes its owned descriptor', () => {
  const io = fixture().add(CD, 'file', Buffer.alloc(65536, 65));
  const item = F.reader(io).read(CD, 65536, false);
  assert.equal(item.data, null); assert.equal(item.fact.sha256, sha(Buffer.alloc(65536, 65)));
  io.entries.get(CD).data = Buffer.alloc(65537, 65); io.entries.get(CD).size = 65536n;
  refuses(() => F.reader(io).read(CD, 65536, false), 'B0_FACTS_FILE_GROWTH_REFUSED'); assert.equal(io.fds.size, 0);
});
test('CD open/post-read identity replacement stays refused without leaking retained bytes', () => {
  for (const after of [false, true]) {
    const io = fixture(), original = io.fstatSync.bind(io); let count = 0;
    io.fstatSync = fd => { const row = original(fd); if (++count > (after ? 1 : 0)) row.ino = 999999n; return row; };
    refuses(() => F.reader(io).read(CD, 65536, false), after ? 'B0_FACTS_POST_READ_CHANGED' : 'B0_FACTS_OPEN_IDENTITY_REFUSED');
    if (!after) assert.deepEqual(io.readNames, []); assert.equal(io.fds.size, 0);
  }
});
test('adding the inventory basename cannot authorize it as an Ubuntu source Signed-By or a Node repository key', () => {
  assert.throws(() => F.sourceRecord({types: 'deb', uris: 'http://archive.ubuntu.com/ubuntu/', suites: 'noble', components: 'main', 'signed-by': CD}), error => /^B0_FACTS_/.test(error.code));
  assert.equal(F.allowed('/etc/apt/keyrings/nodesource.gpg'), false);
  assert.equal(F.allowed(TRUST + '/some-other.gpg'), false);
});
