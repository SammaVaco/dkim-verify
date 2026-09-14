import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { buildRegistry, providers } from '../scripts/update-keys.mjs';

const project = new URL('../', import.meta.url);
const retrievedAt = '2026-09-11T00:00:00.000Z';
const observation = (source, year) => ({
  source, firstSeenAt: `${year}-01-01T00:00:00.000Z`,
  lastSeenAt: `${year}-02-01T00:00:00.000Z`,
});
const sampleSnapshot = records => ({
  domain: 'gmail.com', url: 'https://archive.zk.email/api/key?domain=gmail.com',
  filename: 'sources/test/gmail.com.json', retrievedAt, text: JSON.stringify(records),
});

test('preserves rotated keys and revocations under a reused selector', () => {
  const records = ['p=old', 'p=new', 'v=DKIM1; p='].map((value, index) => ({
    id: index + 1, domain: 'gmail.com', selector: 'mail', value,
    observations: [observation('live_dns', 2024)],
  }));
  const registry = buildRegistry([sampleSnapshot(records)], retrievedAt);
  assert.deepEqual(registry.keys.map(key => key.record).sort(), records.map(record => record.value).sort());
  assert.equal(registry.providers[0].keyCount, 2);
  assert.equal(registry.providers[0].revocationCount, 1);
});

test('retains older keys on refresh and separate archive records with identical TXT values', () => {
  const records = [1, 2].map(id => ({
    id, domain: 'gmail.com', selector: 'mail', value: 'p=old',
    observations: [observation('live_dns', 2024)],
  }));
  const previous = buildRegistry([sampleSnapshot(records)], retrievedAt);
  const refreshed = buildRegistry([sampleSnapshot([])], retrievedAt, previous);
  assert.equal(refreshed.keys.length, 2);
  assert.deepEqual(refreshed.keys, previous.keys);
});

test('uses observation channels instead of treating recovered dates as DNS history', () => {
  const registry = buildRegistry([sampleSnapshot([{
    id: 1, domain: 'gmail.com', selector: 'old', value: 'p=example',
    firstSeenAt: '2010-01-01T00:00:00.000Z',
    observations: [observation('gcd_recovered', 2021)],
  }])], retrievedAt);
  assert.equal(registry.keys[0].sources[0].type, 'gcd_recovered');
  assert.equal(registry.providers[0].dnsFirstSeenAt, null);
  assert.equal(registry.providers[0].recoveredFirstSeenAt, '2021-01-01T00:00:00.000Z');
  assert.equal(registry.coverage.complete, false);
  assert.equal(registry.coverage.requestedSince, '2021-09-11');
});

test('rejects wrong-domain and malformed archive responses', () => {
  assert.throws(() => buildRegistry([sampleSnapshot({ error: 'unavailable' })], retrievedAt));
  assert.throws(() => buildRegistry([sampleSnapshot([{
    id: 1, domain: 'attacker.test', selector: 'mail', value: 'p=example', observations: [],
  }])], retrievedAt), /domain/);
});

test('every bundled record matches its cited, unmodified source snapshot', async () => {
  const registry = JSON.parse(await readFile(new URL('keys.json', project), 'utf8'));
  assert.equal(registry.schemaVersion, 1);
  assert.equal(registry.coverage.complete, false);
  assert.equal(registry.coverage.requestedSince, '2021-09-11');
  assert.ok(registry.keys.length > 0);
  assert.deepEqual(registry.providers.map(provider => provider.domains), providers.map(provider => provider.domains));
  const snapshots = new Map();
  assert.deepEqual(registry.snapshots.map(snapshot => snapshot.domain).sort(),
    providers.flatMap(provider => provider.domains).sort());
  for (const snapshot of registry.snapshots) {
    const raw = await readFile(new URL(snapshot.snapshot, project), 'utf8');
    assert.equal(createHash('sha256').update(raw).digest('hex'), snapshot.snapshotSha256);
    snapshots.set(snapshot.snapshot, raw);
    for (const archived of JSON.parse(raw)) {
      assert.ok(registry.keys.some(key => key.sources.some(source =>
        source.archiveId === archived.id && source.snapshot === snapshot.snapshot)),
      `${snapshot.domain}: dropped archive record ${archived.id}`);
    }
  }
  for (const key of registry.keys) {
    assert.notEqual(key.domain, 'example.test', 'Synthetic example keys must not enter the provider registry');
    assert.ok(key.sources.length > 0);
    for (const source of key.sources) {
      if (!snapshots.has(source.snapshot)) {
        snapshots.set(source.snapshot, await readFile(new URL(source.snapshot, project), 'utf8'));
      }
      const raw = snapshots.get(source.snapshot);
      assert.equal(createHash('sha256').update(raw).digest('hex'), source.snapshotSha256);
      const archived = JSON.parse(raw).find(record => record.id === source.archiveId);
      assert.ok(archived, `${key.id}: missing cited archive record`);
      assert.equal(archived.domain, key.domain);
      assert.equal(archived.selector, key.selector);
      assert.equal(archived.value, key.record);
      assert.deepEqual(archived.observations, source.observations);
      const citation = new URL(source.url);
      assert.equal(citation.origin, 'https://archive.zk.email');
      assert.equal(citation.searchParams.get('domain'), key.domain);
      assert.equal(citation.searchParams.get('selector'), key.selector);
      assert.ok(Number.isFinite(Date.parse(source.retrievedAt)));
      const channels = new Set(source.observations.map(item => item.source));
      const expectedType = channels.size > 1 ? 'mixed' : [...channels][0] ?? 'unknown';
      assert.equal(source.type, expectedType);
    }
  }
});

test('coverage document explicitly discloses missing five-year history', async () => {
  const coverage = await readFile(new URL('COVERAGE.md', project), 'utf8');
  assert.match(coverage, /not complete/i);
  assert.match(coverage, /2021-09-11/);
  assert.match(coverage, /recovered/i);
  assert.match(coverage, /DNS/);
});
