import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { verifyEmail } from '../dkim.js';
import { verifyWithDns } from '../verify-with-dns.js';

const fixtures = JSON.parse(readFileSync(new URL('./fixtures/vectors.json', import.meta.url)));
const message = name => Buffer.from(fixtures.messages[name], 'base64');
const options = { now: fixtures.verificationTime };

test('the sender summary receives From values from the verifier’s own header parser', async () => {
  const original = message('rsa-relaxed-relaxed');
  const report = await verifyWithDns(original, fixtures.keys, options);
  assert.equal(report.fromHeaders.length, 1);
  assert.match(report.fromHeaders[0], /alice@example\.test/);
  assert.equal(report.signatures[0].status, 'valid');
  const duplicate = await verifyEmail(Buffer.concat([Buffer.from('From: other@example.test\r\n'), original]), fixtures.keys, options);
  assert.equal(duplicate.fromHeaders.length, 2);
  assert.equal(duplicate.signatures[0].code, 'ambiguous-from');
  const unsigned = await verifyEmail(Buffer.from('From: alice@example.test\r\n\r\nHello'), [], options);
  assert.deepEqual(unsigned.fromHeaders, ['alice@example.test']);
  assert.equal(unsigned.signatures[0].code, 'no-signature');
});

test('folding is removed without replacing or decoding the From address', async () => {
  const original = message('rsa-relaxed-relaxed').toString('latin1');
  const folded = Buffer.from(original.replace('From: ', 'From:\r\n\t'), 'latin1');
  const report = await verifyEmail(folded, fixtures.keys, options);
  assert.equal(report.signatures[0].status, 'valid');
  assert.equal(report.fromHeaders.length, 1);
  assert.ok(!report.fromHeaders[0].includes('\r'));
  assert.match(report.fromHeaders[0], /alice@example\.test/);
});

test('partial-body, testing-key and revocation caveats have structured flags', async () => {
  const partial = await verifyEmail(message('partial-body'), fixtures.keys, options);
  assert.equal(partial.signatures[0].bodyLengthLimited, true);
  const keys = [{ ...fixtures.keys[0], record: `${fixtures.keys[0].record}; t=y` },
    { ...fixtures.keys[0], record: 'v=DKIM1; p=' }];
  const report = await verifyEmail(message('rsa-relaxed-relaxed'), keys, options);
  assert.equal(report.signatures[0].status, 'valid');
  assert.equal(report.signatures[0].testingKey, true);
  assert.equal(report.signatures[0].hasRevocation, true);
});

test('non-ASCII whitespace is preserved for conservative sender parsing', async () => {
  const bytes = Buffer.from('From: \xa0alice@example.test\xa0\r\n\r\nHello', 'latin1');
  const report = await verifyEmail(bytes, [], options);
  assert.deepEqual(report.fromHeaders, ['\xa0alice@example.test\xa0']);
});
