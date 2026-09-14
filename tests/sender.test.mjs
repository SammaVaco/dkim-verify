import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { keyProvenance, senderSummary } from '../sender.js';
import { verifyEmail } from '../dkim.js';

const dnsKey = { sources: [{ type: 'dns' }] };
const archivedKey = { sources: [{ observations: [{ source: 'live_dns' }] }] };
const valid = (extra = {}) => ({
  status: 'valid', code: 'verified', domain: 'example.test', signedHeaders: ['from', 'subject'],
  key: dnsKey, ...extra,
});
const report = (signatures = [valid()], from = 'Alice <alice@example.test>') => ({ fromHeaders: [from], signatures });
const summaryFor = (from) => senderSummary(report([valid()], from));

test('a matching DNS-backed signature confirms only the sender domain', () => {
  const result = senderSummary(report());
  assert.equal(result.status, 'confirmed');
  assert.equal(result.code, 'sender-domain-confirmed');
  assert.equal(result.title, 'Sender domain confirmed');
  assert.equal(result.address, 'alice@example.test');
  assert.match(result.explanation, /authorized by example\.test/);
  assert.match(result.explanation, /alice@example\.test.*From/);
  assert.match(result.notes.join(' '), /does not prove.*exact mailbox account.*person/);
  assert.match(result.notes.join(' '), /current DNS/);
  assert.match(result.notes.join(' '), /does not establish when/);
});

test('archived DNS evidence is distinguished from a current lookup', () => {
  const result = senderSummary(report([valid({ key: archivedKey })]));
  assert.equal(result.status, 'confirmed');
  assert.match(result.notes.join(' '), /archive/);
  assert.doesNotMatch(result.notes.join(' '), /current DNS/);
  assert.equal(keyProvenance(archivedKey).kind, 'dns');
  assert.equal(keyProvenance(dnsKey).origin, 'live');
});

for (const [from, address] of [
  ['alice@example.test', 'alice@example.test'],
  ['Alice <Alice+tag@EXAMPLE.TEST>', 'Alice+tag@example.test'],
  ['Alice (the sender) <alice@example.test> (outside comment)', 'alice@example.test'],
  ['(nested (address@evil.test)) alice(comment) @ (domain) example.test', 'alice@example.test'],
  ['"CEO <boss@evil.test>" <alice@example.test>', 'alice@example.test'],
  ['"boss@evil.test" <alice@example.test>', 'alice@example.test'],
  ['"Doe, Alice" <alice@example.test>', 'alice@example.test'],
  ['=?UTF-8?Q?Boss=40evil.test?= <alice@example.test>', 'alice@example.test'],
  ['José <alice@example.test>', 'alice@example.test'],
  ['"a@b"@example.test', '"a@b"@example.test'],
  ['"a\\\"b"@example.test', '"a\\\"b"@example.test'],
  ['Display <"a(b)c"@example.test>', '"a(b)c"@example.test'],
  ['Display <"a\\(b"@example.test>', '"a\\(b"@example.test'],
  ['alice+tag!#$%&\'*-/=?^_`{|}~@example.test', 'alice+tag!#$%&\'*-/=?^_`{|}~@example.test'],
]) {
  test(`unambiguous From address: ${from}`, () => {
    const result = summaryFor(from);
    assert.equal(result.status, 'confirmed');
    assert.equal(result.address, address);
  });
}

for (const from of [
  'alice@example.test, other@evil.test',
  'Alice <alice@example.test>, Other <other@evil.test>',
  'Group:alice@example.test;',
  '<@relay.test:alice@example.test>',
  '<alice@example.test> garbage',
  '<alice@example.test><other@evil.test>',
  'boss@evil.test <alice@example.test>',
  '"unclosed <alice@example.test>',
  'Alice <alice@example.test',
  'Alice alice@example.test>',
  'Alice (unclosed <alice@example.test>',
  'Alice ) <alice@example.test>',
  'ali(comment)ce@example.test',
  'alice@exam(comment)ple.test',
  'ali ce@example.test',
  '.alice@example.test',
  'alice..smith@example.test',
  'alice.@example.test',
  'alice@-example.test',
  'alice@example-.test',
  'alice@exa_mple.test',
  'alice@example.test.',
  'alice@localhost',
  'alice@[127.0.0.1]',
  'aliçé@example.test',
  'alice@éxample.test',
  'alice@example.test\r\nFrom: other@evil.test',
  'alice@example.test\0',
  'alice@example.test\x7f',
  '\xa0alice@example.test\xa0',
  'Alice <\xa0alice@example.test>',
  'Alice <alice@example.test>\xa0',
  `${'a'.repeat(65)}@example.test`,
  `alice@${'a'.repeat(64)}.test`,
  `${'A'.repeat(8192)} <alice@example.test>`,
]) {
  test(`unsupported or ambiguous From is never confirmed: ${from.slice(0, 90)}`, () => {
    const result = summaryFor(from);
    assert.equal(result.status, 'unconfirmed');
    assert.equal(result.code, 'unsupported-from');
    assert.equal(result.address, null);
    assert.equal(result.title, 'Sender not confirmed');
  });
}

test('missing and duplicate From fields are not attributed to one displayed address', () => {
  assert.equal(senderSummary({ fromHeaders: [], signatures: [valid()] }).code, 'missing-from');
  assert.equal(senderSummary({ fromHeaders: ['alice@example.test', 'other@evil.test'], signatures: [valid()] }).code, 'ambiguous-from');
  assert.equal(senderSummary({ signatures: [valid()] }).status, 'unconfirmed');
});

test('domain comparison is exact and case insensitive, not a suffix or provider guess', () => {
  assert.equal(senderSummary(report([valid({ domain: 'EXAMPLE.TEST' })])).status, 'confirmed');
  for (const domain of ['example.test.evil.test', 'mail.example.test', 'test', 'otherexample.test', 'provider.test']) {
    const result = senderSummary(report([valid({ domain })]));
    assert.equal(result.status, 'unconfirmed');
    assert.equal(result.code, 'different-signing-domain');
    assert.match(result.explanation, /different domain/);
  }
});

test('a misleading display-name address cannot borrow another domain’s valid signature', () => {
  const result = summaryFor('"alice@example.test" <attacker@evil.test>');
  assert.equal(result.address, 'attacker@evil.test');
  assert.equal(result.status, 'unconfirmed');
  assert.equal(result.code, 'different-signing-domain');
  assert.doesNotMatch(result.explanation, /for alice@example\.test/);
});

test('manually supplied and reconstructed keys cannot confirm domain authorization', () => {
  for (const key of [undefined, { sources: [{ type: 'manual' }] }, { sources: [{ observations: [{ source: 'gcd_recovered' }] }] }]) {
    const result = senderSummary(report([valid({ key })]));
    assert.equal(result.status, 'unconfirmed');
    assert.equal(result.code, 'unconfirmed-key');
    assert.match(result.explanation, /no DNS evidence/);
  }
});

test('a supposedly valid result without a signed From cannot confirm the sender', () => {
  const result = senderSummary(report([valid({ signedHeaders: ['subject'] })]));
  assert.equal(result.status, 'unconfirmed');
  assert.equal(result.code, 'unsigned-from');
});

for (const [flag, caution] of [
  ['bodyLengthLimited', /only part|additional text|text can be added/],
  ['testingKey', /testing.*not.*endorsement/],
  ['hasRevocation', /withdrawn.*authorized/],
]) {
  test(`a matching ${flag} signature retains a visible limitation`, () => {
    const result = senderSummary(report([valid({ [flag]: true })]));
    assert.equal(result.status, 'limited');
    assert.equal(result.code, 'sender-domain-limited');
    assert.equal(result.title, 'Sender check has limits');
    assert.match(result.notes.join(' '), caution);
    assert.match(result.notes.join(' '), /exact mailbox account/);
  });
}

test('clean matching signatures win over failed, unrelated and limited signatures in any order', () => {
  const mixed = [
    valid({ status: 'invalid', code: 'signature-mismatch' }),
    valid({ domain: 'other.test' }),
    valid({ bodyLengthLimited: true }),
    valid(),
  ];
  for (const signatures of [mixed, mixed.toReversed()]) {
    const result = senderSummary(report(signatures));
    assert.equal(result.status, 'confirmed');
    assert.doesNotMatch(result.notes.join(' '), /only part|text can be added/);
  }
});

test('a valid matching signature with all limitations shows every caveat', () => {
  const result = senderSummary(report([valid({ bodyLengthLimited: true, testingKey: true, hasRevocation: true })]));
  assert.equal(result.status, 'limited');
  assert.match(result.notes.join(' '), /text can be added/);
  assert.match(result.notes.join(' '), /testing/);
  assert.match(result.notes.join(' '), /withdrawn/);
});

for (const [status, code, expected, explanation] of [
  ['unverifiable', 'missing-key', 'missing-key', /public information.*unavailable/],
  ['unverifiable', 'dns-not-found', 'dns-not-found', /public information.*unavailable/],
  ['unverifiable', 'dns-unavailable', 'dns-unavailable', /public information.*unavailable/],
  ['expired', 'expired-signature', 'expired-signature', /expired.*selected/],
  ['unverifiable', 'future-timestamp', 'future-timestamp', /after.*selected/],
  ['unverifiable', 'revoked-key', 'revoked-key', /withdrawn/],
  ['unverifiable', 'unsupported-algorithm', 'unsupported-algorithm', /could not complete/],
]) {
  test(`${code} is not evidence of a forged From address`, () => {
    const result = senderSummary(report([valid({ status, code })]));
    assert.equal(result.status, 'unconfirmed');
    assert.equal(result.code, expected);
    assert.equal(result.title, 'Sender not confirmed');
    assert.match(result.explanation, explanation);
    assert.match(result.explanation + result.notes.join(' '), /not.*(?:proof|evidence)|does not.*forged/);
  });
}

test('failed signatures explain uncertainty instead of claiming a forged sender or a specific changed header', () => {
  const result = senderSummary(report([valid({ status: 'invalid', code: 'signature-mismatch' })]));
  assert.equal(result.status, 'failed');
  assert.equal(result.code, 'signature-failed');
  assert.equal(result.title, 'Sender not confirmed');
  assert.match(result.explanation, /does not validate/);
  assert.match(result.explanation, /may have changed/);
  assert.match(result.explanation, /historical key/);
  assert.doesNotMatch(result.explanation, /From.*(?:was|has been) changed/);
  assert.match(result.explanation, /does not prove.*forged/);
});

test('a missing matching key is not hidden by another failed matching signature', () => {
  const signatures = [valid({ status: 'invalid', code: 'signature-mismatch' }), valid({ status: 'unverifiable', code: 'missing-key' })];
  assert.equal(senderSummary(report(signatures)).status, 'unconfirmed');
  assert.equal(senderSummary(report(signatures)).code, 'missing-key');
});

test('unsigned emails have a sender-focused explanation', () => {
  for (const signatures of [[], [{ status: 'unverifiable', code: 'no-signature' }]]) {
    const result = senderSummary(report(signatures));
    assert.equal(result.status, 'unconfirmed');
    assert.equal(result.code, 'no-signature');
    assert.match(result.explanation, /no.*signature/i);
  }
});

test('real signed fixture, changed From, and body-length limit produce the appropriate sender verdicts', async () => {
  const fixtures = JSON.parse(readFileSync(new URL('./fixtures/vectors.json', import.meta.url)));
  const keys = fixtures.keys.map(key => ({ ...key, sources: dnsKey.sources }));
  const bytes = Buffer.from(fixtures.messages['rsa-relaxed-relaxed'], 'base64');
  const verified = await verifyEmail(bytes, keys, { now: fixtures.verificationTime });
  assert.equal(senderSummary(verified).status, 'confirmed');
  assert.equal(senderSummary(verified).address, 'alice@example.test');
  const changed = Buffer.from(bytes.toString('latin1').replace('Alice', 'Impostor'), 'latin1');
  assert.notDeepEqual(changed, bytes);
  assert.equal(senderSummary(await verifyEmail(changed, keys, { now: fixtures.verificationTime })).status, 'failed');
  const limited = Buffer.from(fixtures.messages['partial-body'], 'base64');
  assert.equal(senderSummary(await verifyEmail(limited, keys, { now: fixtures.verificationTime })).status, 'limited');
});
