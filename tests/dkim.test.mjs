import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { verifyEmail } from '../dkim.js';

const fixture = await readFile(new URL('./fixtures/from-demo.eml', import.meta.url));
const fixtureKey = {
  domain: 'example.test', selector: 'demo', sources: [],
  record: (await readFile(new URL('./fixtures/from-demo-public-key.txt', import.meta.url), 'utf8')).trim(),
};
const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
const ed25519 = generateKeyPairSync('ed25519');
const now = 1789084800;
const bytes = text => Buffer.from(text, 'latin1');
const sha256 = content => createHash('sha256').update(content).digest();

function signedMessage({ body = 'Hello.\r\n', signedBody = body, headers = ['From: Alice <alice@example.test>'],
  selected = headers, headerMode = 'simple', bodyMode = 'simple', algorithm = 'rsa-sha256',
  extra = '', pair = rsa, recordExtra = '', keyFormat = 'spki', signedNames,
  suffix = '', canonicalHeaders, signaturePrefix = 'DKIM-Signature: ' } = {}) {
  const headerNames = signedNames ?? selected.map(header => header.slice(0, header.indexOf(':')).toLowerCase()).join(':');
  const canonical = header => headerMode === 'simple' ? header : header.replace(/\r\n/g, '').replace(/[ \t]+/g, ' ')
    .replace(/^([^:]+): */, (_, name) => `${name.trim().toLowerCase()}:`).replace(/ +$/, '');
  const signatureHeader = `${signaturePrefix}v=1; a=${algorithm}; c=${headerMode}/${bodyMode}; d=example.test; s=test; h=${headerNames}; ${extra}bh=${sha256(bytes(signedBody)).toString('base64')}; b=`;
  const signingInput = bytes(`${(canonicalHeaders ?? selected.map(canonical)).join('\r\n')}\r\n${canonical(signatureHeader + suffix)}`);
  const signature = sign(algorithm === 'ed25519-sha256' ? null : 'sha256',
    algorithm === 'ed25519-sha256' ? sha256(signingInput) : signingInput, pair.privateKey).toString('base64');
  const publicBytes = pair.publicKey.export({ type: keyFormat, format: 'der' });
  const key = { domain: 'example.test', selector: 'test', sources: [],
    record: `v=DKIM1; k=${algorithm === 'ed25519-sha256' ? 'ed25519' : 'rsa'}; ${recordExtra}p=${(algorithm === 'ed25519-sha256' ? publicBytes.subarray(-32) : publicBytes).toString('base64')}` };
  return { message: bytes(`${signatureHeader}${signature}${suffix}\r\n${headers.join('\r\n')}\r\n\r\n${body}`), key };
}

async function check(message, keys = [fixtureKey], options = { now }) {
  return (await verifyEmail(message, keys, options)).signatures[0];
}

test('dkimpy fixture verifies, exposes the exact key, and has no age timeout', async () => {
  const report = await check(fixture, [fixtureKey], { now: 4102444800 });
  assert.equal(report.status, 'valid');
  assert.equal(report.bodyHashMatches, true);
  assert.equal(report.signatureMatches, true);
  assert.equal(report.key, fixtureKey);
  assert.match(report.keyFingerprint, /^[a-f0-9]{64}$/);
});

test('changing From invalidates headers without pretending to identify the changed field', async () => {
  const report = await check(bytes(fixture.toString('latin1').replace('alice@example.test>', 'mallory@example.test>')));
  assert.equal(report.status, 'invalid');
  assert.equal(report.code, 'signature-mismatch');
  assert.equal(report.bodyHashMatches, true);
  assert.equal(report.signatureMatches, false);
  assert.match(report.explanation, /header|signature|key/i);
});

test('a modified body has an understandable and distinct failure', async () => {
  const report = await check(bytes(fixture.toString('latin1').replace('Hello, Bob.', 'Goodbye, Bob.')));
  assert.equal(report.code, 'body-mismatch');
  assert.equal(report.bodyHashMatches, false);
  assert.match(report.explanation, /body|content/i);
});

test('unknown selector is unverifiable, not evidence of changed mail', async () => {
  assert.equal((await check(fixture, [])).status, 'unverifiable');
  assert.equal((await check(fixture, [])).code, 'missing-key');
});

test('RSA simple, relaxed, PKCS1, and Ed25519 signatures verify', async () => {
  for (const options of [{}, { headerMode: 'relaxed' }, { keyFormat: 'pkcs1' }, { algorithm: 'ed25519-sha256', pair: ed25519 }]) {
    const { message, key } = signedMessage(options);
    assert.equal((await check(message, [key])).status, 'valid', JSON.stringify(options));
  }
});

test('empty simple body hashes CRLF and empty relaxed body hashes zero bytes', async () => {
  for (const bodyMode of ['simple', 'relaxed']) {
    const { message, key } = signedMessage({ body: '', bodyMode, signedBody: bodyMode === 'simple' ? '\r\n' : '' });
    assert.equal((await check(message, [key])).status, 'valid');
  }
});

test('relaxed rules tolerate folding and whitespace without rewriting non-ASCII bytes', async () => {
  const { message, key } = signedMessage({
    headerMode: 'relaxed', bodyMode: 'relaxed',
    headers: ['From:  Alice\r\n \t<alice@example.test>'],
    body: 'H\xe9llo. \t\r\n\r\n \t\r\n', signedBody: 'H\xe9llo.\r\n',
  });
  assert.equal((await check(message, [key])).status, 'valid');
});

test('LF export normalization preserves the original DKIM result', async () => {
  const { message, key } = signedMessage();
  assert.equal((await check(bytes(message.toString('latin1').replace(/\r\n/g, '\n')), [key])).status, 'valid');
});

test('signed repeated headers select bottom-up and absent oversigned fields add no bytes', async () => {
  const headers = ['From: alice@example.test', 'X-Note: first', 'X-Note: second'];
  const { message, key } = signedMessage({ headers, selected: [headers[0], headers[2], headers[1]], signedNames: 'from:x-note:x-note:x-absent' });
  assert.equal((await check(message, [key])).status, 'valid');
  assert.equal((await check(bytes(message.toString('latin1').replace('X-Note: first', 'X-Note: changed')), [key])).status, 'invalid');
});

test('b value removal preserves a following tag and its whitespace', async () => {
  const { message, key } = signedMessage({ suffix: '; note=retained' });
  const folded = message.toString('latin1').replace(/b=([^;]+);/, (_, signature) => `b= \r\n ${signature} \r\n \t;`);
  assert.equal((await check(bytes(folded), [key])).status, 'valid');
});

test('multiple signatures report independently, trying rotated keys for the same selector', async () => {
  const { message, key } = signedMessage();
  const signatureHeader = message.toString('latin1').split('\r\n')[0];
  const report = await verifyEmail(bytes(`${signatureHeader}\r\n${message.toString('latin1')}`), [{ ...key, record: fixtureKey.record }, key], { now });
  assert.deepEqual(report.signatures.map(signature => signature.status), ['valid', 'valid']);
  assert.equal(report.signatures[0].key, key);
});

test('body length limits warn about unsigned bytes and reject lengths beyond the body', async () => {
  const { message, key } = signedMessage({ body: 'Hello.\r\nAdded text\r\n', signedBody: 'Hello.\r\n', extra: 'l=8; ' });
  const report = await check(message, [key]);
  assert.equal(report.status, 'valid');
  assert.match(report.warnings.join(' '), /unsigned|not protected/i);
  assert.equal((await check(bytes(message.toString('latin1').replace('l=8;', 'l=999;')), [key])).code, 'body-length');
});

test('expiration and future times are explicit, with an optional historical clock', async () => {
  const { message, key } = signedMessage({ extra: 't=1700000000; x=1750000000; ' });
  const expired = await check(message, [key]);
  assert.equal(expired.status, 'expired');
  assert.equal(expired.signatureMatches, true);
  assert.equal((await check(message, [key], { now: 1720000000 })).status, 'valid');
  assert.equal((await check(message, [key], { now: 1600000000 })).code, 'future-timestamp');
});

test('revoked, malformed, weak, and restricted keys cannot produce valid reports', async () => {
  const { message, key } = signedMessage();
  for (const record of ['v=DKIM1; p=', 'v=DKIM1; p=bad!', `${key.record}; h=sha1`, `${key.record}; s=other`, `${key.record}; p=AAAA`]) {
    assert.notEqual((await check(message, [{ ...key, record }])).status, 'valid', record);
  }
  const weak = signedMessage({ pair: generateKeyPairSync('rsa', { modulusLength: 512 }) });
  assert.equal((await check(weak.message, [weak.key])).code, 'weak-key');
});

test('identity must belong to signing domain and respect the strict identity key flag', async () => {
  const unrelated = signedMessage({ extra: 'i=@unrelated.test; ' });
  assert.equal((await check(unrelated.message, [unrelated.key])).code, 'identity-domain');
  const child = signedMessage({ extra: 'i=@child.example.test; ' });
  assert.equal((await check(child.message, [child.key])).status, 'valid');
  assert.equal((await check(child.message, [{ ...child.key, record: `${child.key.record}; t=s` }])).code, 'key-restriction');
});

test('missing signed From, ambiguous From, obsolete algorithms, and duplicate tags are rejected', async () => {
  const { message, key } = signedMessage();
  const original = message.toString('latin1');
  for (const [modified, code] of [
    [original.replace('h=from;', 'h=to;'), 'unsigned-from'],
    [original.replace('\r\n\r\n', '\r\nFrom: attacker@example.test\r\n\r\n'), 'ambiguous-from'],
    [original.replace('a=rsa-sha256;', 'a=rsa-sha1;'), 'unsupported-algorithm'],
    [original.replace('v=1;', 'v=1; v=1;'), 'malformed-signature'],
    [original.replace('bh=', 'bh=!'), 'malformed-signature'],
  ]) assert.equal((await check(bytes(modified), [key])).code, code);
});

test('malformed, unsigned, and oversized emails return useful reports', async () => {
  assert.equal((await check(bytes('From: alice@example.test\r\n\r\nHello'))).code, 'no-signature');
  assert.equal((await check(bytes('not an email'))).code, 'malformed-message');
  assert.equal((await check(new Uint8Array(20 * 1024 * 1024 + 1))).code, 'size-limit');
  assert.equal((await check(bytes(`From: ${'a'.repeat(1024 * 1024)}\r\n\r\nBody`))).code, 'size-limit');
  assert.equal((await check(bytes(`${'DKIM-Signature: v=1\r\n'.repeat(101)}From: alice@example.test\r\n\r\nBody`))).code, 'signature-limit');
  assert.equal((await check(fixture, [fixtureKey], { now: NaN })).code, 'invalid-time');
});

test('archived revocation is disclosed alongside a matching historical key', async () => {
  const { message, key } = signedMessage();
  const report = await check(message, [key, { ...key, record: 'v=DKIM1; p=' }]);
  assert.equal(report.status, 'valid');
  assert.match(report.warnings.join(' '), /revocation|revoked/i);
});

test('quoted identities remain valid while malformed identities and key flag lists fail', async () => {
  for (const identity of ['=22alice=20smith=22@example.test', 'alice+tag@example.test', '@example.test']) {
    const { message, key } = signedMessage({ extra: `i=${identity}; ` });
    assert.equal((await check(message, [key])).status, 'valid', identity);
  }
  for (const identity of ['alice@@example.test', '.alice@example.test', 'alice=00@example.test', 'alice=2f@example.test']) {
    const { message, key } = signedMessage({ extra: `i=${identity}; ` });
    assert.notEqual((await check(message, [key])).status, 'valid', identity);
  }
  const { message, key } = signedMessage();
  for (const restriction of ['t=', 't=y::s', 's=email:', 'h=sha256:']) {
    assert.notEqual((await check(message, [{ ...key, record: `${key.record}; ${restriction}` }])).status, 'valid', restriction);
  }
});

test('body normalization handles long internal blank-line runs', async () => {
  const body = `First\r\n${'\r\n'.repeat(10000)}Last\r\n`;
  const { message, key } = signedMessage({ body });
  assert.equal((await check(message, [key])).status, 'valid');
});

test('query methods permit extensions but reject malformed lists', async () => {
  const valid = signedMessage({ extra: 'q=future/arg=20value:dns/txt; ' });
  assert.equal((await check(valid.message, [valid.key])).status, 'valid');
  for (const query of ['dns/txt::', 'dns/txt:!bad', 'dns/txt:method/bad=GG']) {
    const { message, key } = signedMessage({ extra: `q=${query}; ` });
    assert.equal((await check(message, [key])).code, 'malformed-signature');
  }
});

test('internationalized DKIM identifiers report unsupported rather than invalid', async () => {
  for (const extra of ['i==C3=A9@example.test; ', 'i=\xc3\xa9@example.test; ']) {
    const { message, key } = signedMessage({ extra });
    const report = await check(message, [key]);
    assert.equal(report.status, 'unverifiable');
    assert.equal(report.code, 'unsupported-internationalized');
  }
  const { message, key } = signedMessage();
  for (const [original, internationalized] of [['d=example.test', 'd=\xc3\xa9xample.test'], ['s=test', 's=t\xc3\xa9st']]) {
    const report = await check(bytes(message.toString('latin1').replace(original, internationalized)), [key]);
    assert.equal(report.status, 'unverifiable');
    assert.equal(report.code, 'unsupported-internationalized');
  }
});
