'use strict';
// Source code under test only; fake filesystem, no probe main or image process.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const hostfs = require('node:fs');
const vm = require('node:vm');
const F = require('./facts.cjs');
const source = hostfs.readFileSync(__dirname + '/facts.cjs', 'utf8');
const SOURCE = '/etc/apt/sources.list.d', TRUST = '/etc/apt/trusted.gpg.d';
function internals(overrides = {}) {
  const mod = {exports: {}};
  const sandbox = {module: mod, Buffer, process: {}, ...overrides};
  sandbox.require = name => {
    if (name === 'node:fs') return {};
    assert.ok(['node:crypto', 'node:path', 'node:util'].includes(name));
    return overrides.crypto && name === 'node:crypto' ? overrides.crypto : require(name);
  };
  vm.runInNewContext(source + '\nmodule.exports._failureJSON = raw => failureFacts(JSON.parse(raw));', sandbox);
  return mod.exports;
}
const privateF = internals();
class DirectoryFS {
  constructor(directory, names) { this.directory = directory; this.names = names; this.stats = []; this.reads = 0; this.opens = 0; this.closes = 0; }
  lstatSync(name) {
    this.stats.push(name);
    assert.ok(['/', '/etc', '/etc/apt', this.directory].includes(name));
    return {isDirectory: () => true, uid: 0n, gid: 0n, mode: 0o40755n};
  }
  opendirSync(name, options) {
    assert.equal(name, this.directory); assert.equal(options.bufferSize, 1);
    let offset = 0;
    return {readSync: () => { this.reads++; return offset < this.names.length ? {name: this.names[offset++]} : null; }, closeSync: () => { this.closes++; }};
  }
  openSync() { this.opens++; throw new Error('PRIVATE CONTENT MUST NOT BE OPENED'); }
  readSync() { throw new Error('PRIVATE CONTENT MUST NOT BE READ'); }
  readlinkSync() { throw new Error('PRIVATE CONTENT MUST NOT BE READ'); }
}
function predicate(directory) {
  return directory === SOURCE ? name => /^[A-Za-z0-9][A-Za-z0-9_.-]{0,120}\.(list|sources)$/.test(name) : name => ['ubuntu-keyring-2012-archive.gpg', 'ubuntu-keyring-2018-archive.gpg'].includes(name);
}
function refusal(directory, names, implementation = F) {
  const io = new DirectoryFS(directory, names);
  let caught;
  assert.throws(() => implementation.reader(io).directory(directory, 32, predicate(directory)), error => {
    caught = error; return error.code === 'B0_FACTS_DIRECTORY_ENTRY_REFUSED';
  });
  assert.equal(io.closes, 1); assert.equal(io.opens, 0);
  return {error: caught, io};
}
function parsedFailure(error) { return JSON.parse(privateF.encodeBounded(privateF._failureJSON(JSON.stringify({...error, message: error.message, path: error.path, content: error.content})))); }

test('sources/trust failure contexts and UTF8 digest are exact, not raw basename', () => {
  for (const [directory, context] of [[SOURCE, 'sources_list_d'], [TRUST, 'trusted_gpg_d']]) {
    const name = 'SYNTHETIC-rejected-entry.key';
    const {error, io} = refusal(directory, [name, 'never-inspect-next.key']);
    const facts = parsedFailure(error), diagnostic = facts.directory_entry_diagnostic;
    assert.deepEqual(diagnostic, {code: 'B0_FACTS_DIRECTORY_ENTRY_REFUSED', directory_context: context, basename_status: 'hashed',
      basename_utf8_bytes: Buffer.byteLength(name), basename_sha256: crypto.createHash('sha256').update(name).digest('hex')});
    assert.equal(io.reads, 1); assert.equal(io.stats.length, 4);
    const encoded = JSON.stringify(facts);
    assert.equal(encoded.includes(name), false); assert.equal(encoded.includes(directory), false);
    assert.equal(encoded.includes('never-inspect'), false); assert.ok(Buffer.byteLength(JSON.stringify(diagnostic)) <= 1024);
    assert.equal(facts.code, 'B0_FACTS_DIRECTORY_ENTRY_REFUSED'); assert.equal(facts.ok, false);
    assert.equal(facts.stage0_passed, false); assert.equal(facts.authority, false); assert.equal(facts.release_qualified, false);
    assert.equal(facts.phase, 'public_file_inventory_only');
  }
});

test('accepted production directory predicates and results are unchanged', () => {
  for (const [directory, names] of [[SOURCE, ['ubuntu.sources', 'nodesource.list']], [TRUST, ['ubuntu-keyring-2012-archive.gpg', 'ubuntu-keyring-2018-archive.gpg']]]) {
    const io = new DirectoryFS(directory, names);
    const row = F.reader(io).directory(directory, 32, predicate(directory));
    assert.deepEqual(row, {present: true, entries: names.sort().map(name => directory + '/' + name)});
    assert.equal(Object.hasOwn(row, 'directory_entry_diagnostic'), false); assert.equal(io.closes, 1); assert.equal(io.opens, 0);
  }
});

test('Unicode hashes preserve UTF8 bytes and NFC/NFD distinction without raw output', () => {
  const results = [];
  for (const name of ['é.key', 'é.key', '😀.key']) {
    const facts = parsedFailure(refusal(TRUST, [name]).error);
    const diagnostic = facts.directory_entry_diagnostic;
    assert.equal(diagnostic.basename_status, 'hashed'); assert.equal(diagnostic.basename_utf8_bytes, Buffer.byteLength(name));
    assert.equal(diagnostic.basename_sha256, crypto.createHash('sha256').update(name).digest('hex'));
    assert.equal(JSON.stringify(facts).includes(name), false); results.push(diagnostic.basename_sha256);
  }
  assert.notEqual(results[0], results[1]);
});

test('exact512 UTF8 bytes hash; +1/Unicode excess return bounded unknown', () => {
  for (const name of ['a'.repeat(512), '😀'.repeat(128)]) {
    const diagnostic = parsedFailure(refusal(TRUST, [name]).error).directory_entry_diagnostic;
    assert.equal(diagnostic.basename_status, 'hashed'); assert.equal(diagnostic.basename_utf8_bytes, 512);
  }
  for (const name of ['a'.repeat(513), '😀'.repeat(129), 'é'.repeat(512)]) {
    const diagnostic = parsedFailure(refusal(TRUST, [name]).error).directory_entry_diagnostic;
    assert.equal(diagnostic.basename_status, 'unavailable_or_refused');
    assert.equal(diagnostic.basename_utf8_bytes, null); assert.equal(diagnostic.basename_sha256, null);
  }
});

test('malformed values do not coerce to strings or export controls/path/error bytes', () => {
  const malformed = ['', '.', '..', 'a/b', 'a\\b', 'name\nPRIVATE', 'name\0PRIVATE', '\x85', '\ufffd', '\ud800', '\udfff', null, undefined, 1, false, Symbol('PRIVATE'), {toString() { throw new Error('COERCION FORBIDDEN'); }}];
  for (const name of malformed) {
    const facts = parsedFailure(refusal(TRUST, [name]).error);
    assert.equal(facts.directory_entry_diagnostic.basename_status, 'unavailable_or_refused');
    assert.equal(JSON.stringify(facts).includes('PRIVATE'), false);
  }
});

test('oversized string is rejected without UTF8 counting, allocation or hashing', () => {
  const instrumented = internals({Buffer: {byteLength() { throw new Error('UTF8 BEFORE BOUND'); }}, crypto: {createHash() { throw new Error('HASH BEFORE BOUND'); }}});
  const {error, io} = refusal(TRUST, ['x'.repeat(1024 * 1024)], instrumented);
  assert.equal(error.directory_entry_diagnostic.basename_status, 'unavailable_or_refused'); assert.equal(io.reads, 1);
});

test('failure builder never exports message/path/content or nonmatching diagnostics', () => {
  const valid = refusal(TRUST, ['SYNTHETIC.key']).error.directory_entry_diagnostic;
  for (const code of ['B0_FACTS_STAT_REFUSED', 'PRIVATE ERROR']) {
    const error = Object.assign(new Error('PRIVATE error'), {code, path: '/root/PRIVATE', content: 'PRIVATE', directory_entry_diagnostic: valid});
    const facts = parsedFailure(error);
    assert.equal(Object.hasOwn(facts, 'directory_entry_diagnostic'), false); assert.equal(JSON.stringify(facts).includes('PRIVATE'), false);
  }
  for (const mutation of [{...valid, raw_name: 'PRIVATE'}, {...valid, directory_context: '/root/PRIVATE'}, {...valid, basename_utf8_bytes: true}, {...valid, basename_sha256: 'PRIVATE'}, {...valid, code: 'PRIVATE'}]) {
    const facts = parsedFailure({code: 'B0_FACTS_DIRECTORY_ENTRY_REFUSED', directory_entry_diagnostic: mutation, message: 'PRIVATE'});
    assert.equal(Object.hasOwn(facts, 'directory_entry_diagnostic'), false); assert.equal(JSON.stringify(facts).includes('PRIVATE'), false);
  }
});

test('directory budget/scope errors remain separate and no new entry is inspected', () => {
  const io = new DirectoryFS(TRUST, ['ubuntu-keyring-2012-archive.gpg', 'SYNTHETIC.key']);
  assert.throws(() => F.reader(io).directory(TRUST, 0, predicate(TRUST)), error => error.code === 'B0_FACTS_DIRECTORY_BUDGET');
  assert.equal(io.reads, 1); assert.equal(io.opens, 0); assert.equal(io.closes, 1);
  assert.throws(() => F.reader(io).directory('/root', 32, () => true), error => error.code === 'B0_FACTS_DIRECTORY_SCOPE');
});

test('entrypoint exit42/output/cleanup-facing phase are unchanged, main is not called', () => {
  assert.ok(source.includes('process.exitCode = result.ok ? 0 : 42;'));
  assert.ok(source.includes("fs.writeFileSync('/evidence/facts.json', encoded, {flag: 'wx', mode: 0o600});"));
  assert.ok(source.includes('if (require.main === module) main();'));
});
