import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { verifyWithDns } from '../verify-with-dns.js';

const fixtures = JSON.parse(readFileSync(new URL('./fixtures/vectors.json', import.meta.url)));
const original = Buffer.from(fixtures.messages['rsa-relaxed-relaxed'], 'base64');
const key = fixtures.keys[0];
const now = fixtures.verificationTime;

function resolver(calls, records = fixtures.keys) {
  return async (url, options) => {
    calls.push({ url, options });
    const name = new URL(url).searchParams.get('name');
    const found = records.find(record => name === `${record.selector}._domainkey.${record.domain}`);
    return new Response(JSON.stringify({ Status: found ? 0 : 3, Question: [{ name, type: 16 }],
      Answer: found ? [{ name, type: 16, data: JSON.stringify(found.record) }] : [] }));
  };
}

test('a missing key is fetched and verified locally, with current DNS evidence', async () => {
  const calls = [];
  const report = await verifyWithDns(original, [], { now, dnsFallback: true, fetchImpl: resolver(calls) });
  const result = report.signatures[0];
  assert.equal(result.status, 'valid');
  assert.equal(result.key.record, key.record);
  assert.equal(result.key.sources[0].type, 'dns');
  assert.equal(result.keyFingerprint.length, 64);
  assert.equal(calls.length, 1);
});

test('offline mode and registry matches never request DNS, including a wrong registered key', async () => {
  const fetchImpl = () => { throw new Error('Unexpected network request'); };
  assert.equal((await verifyWithDns(original, [], { now, fetchImpl })).signatures[0].code, 'missing-key');
  assert.equal((await verifyWithDns(original, [], { now, dnsFallback: false, fetchImpl })).signatures[0].code, 'missing-key');
  assert.equal((await verifyWithDns(original, fixtures.keys, { now, dnsFallback: true, fetchImpl })).signatures[0].status, 'valid');
  const wrong = [{ ...key, record: 'v=DKIM1; p=invalid' }];
  assert.notEqual((await verifyWithDns(original, wrong, { now, dnsFallback: true, fetchImpl })).signatures[0].code, 'missing-key');
});

test('duplicate signatures share a lookup and source evidence', async () => {
  const header = original.subarray(0, original.indexOf('\r\nFrom:') + 2);
  assert.match(header.toString(), /^DKIM-Signature:/);
  const calls = [];
  const report = await verifyWithDns(Buffer.concat([header, original]), [], { now, dnsFallback: true, fetchImpl: resolver(calls) });
  assert.deepEqual(report.signatures.map(result => result.status), ['valid', 'valid']);
  assert.equal(calls.length, 1);
});

test('DNS absence is unable to verify, not proof of alteration', async () => {
  const report = await verifyWithDns(original, [], { now, dnsFallback: true, fetchImpl: resolver([], []) });
  assert.equal(report.signatures[0].status, 'unverifiable');
  assert.equal(report.signatures[0].code, 'dns-not-found');
  assert.match(report.signatures[0].explanation, /historical|removed|rotat/i);
});

test('changed From still fails after lookup, with the fetched key available for inspection', async () => {
  const changed = Buffer.from(original.toString('latin1').replace('From:', 'From: Changed '), 'latin1');
  const report = await verifyWithDns(changed, [], { now, dnsFallback: true, fetchImpl: resolver([]) });
  assert.equal(report.signatures[0].code, 'signature-mismatch');
  assert.equal(report.signatures[0].bodyHashMatches, true);
  assert.equal(report.signatures[0].dnsLookup.key.record, key.record);
  assert.equal(report.signatures[0].key, undefined);
});

test('body failures do not make pointless DNS requests', async () => {
  const changed = Buffer.concat([original, Buffer.from('Changed body')]);
  const report = await verifyWithDns(changed, [], { now, dnsFallback: true,
    fetchImpl: () => { throw new Error('Unexpected network request'); } });
  assert.equal(report.signatures[0].code, 'body-mismatch');
});

test('cancelling before lookup avoids sending any names', async () => {
  const controller = new AbortController();
  controller.abort();
  const report = await verifyWithDns(original, [], { now, dnsFallback: true, signal: controller.signal,
    fetchImpl: () => { throw new Error('Unexpected network request'); } });
  assert.equal(report.signatures[0].code, 'missing-key');
});

test('a message cannot trigger more than ten distinct key lookups', async () => {
  const header = original.subarray(0, original.indexOf('\r\nFrom:') + 2).toString('latin1');
  const headers = Array.from({ length: 11 }, (_, index) => header.replace('s=rsa;', `s=key${index};`));
  const message = Buffer.concat([Buffer.from(headers.join(''), 'latin1'), original.subarray(header.length)]);
  const calls = [];
  const report = await verifyWithDns(message, [], { now, dnsFallback: true, fetchImpl: resolver(calls, []) });
  assert.equal(calls.length, 10);
  assert.equal(report.signatures[10].status, 'unverifiable');
  assert.equal(report.signatures[10].code, 'dns-limit');
});

test('one lookup failure does not prevent another signature being verified', async () => {
  const message = Buffer.from(fixtures.messages.multiple, 'base64');
  const report = await verifyWithDns(message, [], { now, dnsFallback: true, fetchImpl: resolver([], [key]) });
  assert.deepEqual(report.signatures.map(result => result.status).sort(), ['unverifiable', 'valid']);
});
