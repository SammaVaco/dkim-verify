import assert from 'node:assert/strict';
import test from 'node:test';

import { lookupDkimKey } from '../dns.js';

const keyName = 'demo._domainkey.example.test';
const aliasName = 'demo.keys.provider.test';
const record = 'v=DKIM1; k=rsa; p=YWJj';

function answer(name, type, data) {
  return { name: `${name}.`, type, TTL: 300, data };
}

function response(name, answers = [], status = 0) {
  return { Status: status, TC: false, Question: [{ name: `${name}.`, type: 16 }], Answer: answers };
}

function fakeFetch(replies) {
  const requests = [];
  const fetchImpl = async (url, options) => {
    requests.push({ url: String(url), options });
    const reply = replies[new URL(url).searchParams.get('name')];
    assert.ok(reply, `Unexpected DNS query: ${url}`);
    return new Response(JSON.stringify(reply));
  };
  return { fetchImpl, requests };
}

test('a raw TXT answer returns exact key and auditable, current DNS evidence', async () => {
  const reply = response(keyName, [answer(keyName, 16, record)]);
  const lookup = fakeFetch({ [keyName]: reply });
  const result = await lookupDkimKey('Example.Test', 'Demo', lookup);
  assert.equal(result.key.domain, 'example.test');
  assert.equal(result.key.selector, 'demo');
  assert.equal(result.key.record, record);
  const source = result.key.sources[0];
  assert.equal(source.type, 'dns');
  assert.equal(source.label, 'Google Public DNS');
  assert.ok(Number.isFinite(Date.parse(source.retrievedAt)));
  assert.equal(source.url, lookup.requests[0].url);
  assert.deepEqual(source.responses, [{ url: source.url, response: reply }]);
  const { url, options } = lookup.requests[0];
  const parsed = new URL(url);
  assert.equal(parsed.origin, 'https://dns.google');
  assert.equal(parsed.pathname, '/resolve');
  assert.deepEqual([...parsed.searchParams], [
    ['name', keyName], ['type', 'TXT'], ['edns_client_subnet', '0.0.0.0/0'],
  ]);
  assert.equal(options.method, 'GET');
  assert.equal(options.body, undefined);
  assert.equal(options.credentials, 'omit');
  assert.equal(options.referrerPolicy, 'no-referrer');
  assert.equal(options.redirect, 'error');
});

test('quoted chunks concatenate within one TXT record and decode presentation escapes', async () => {
  const encoded = '  "v=DKIM1; p=YW""Jj; n=\\065\\\\\\\""  ';
  const lookup = fakeFetch({ [keyName]: response(keyName, [answer(keyName, 16, encoded)]) });
  const result = await lookupDkimKey('example.test', 'demo', lookup);
  assert.equal(result.key.record, 'v=DKIM1; p=YWJj; n=A\\"');
});

test('CNAME and TXT in one response are followed without an extra query', async () => {
  const lookup = fakeFetch({ [keyName]: response(keyName, [
    answer(aliasName, 16, record), answer(keyName, 5, aliasName.toUpperCase() + '.'),
  ]) });
  const result = await lookupDkimKey('example.test', 'demo', lookup);
  assert.equal(result.key.record, record);
  assert.equal(lookup.requests.length, 1);
});

test('CNAME-only answers trigger a bounded second query and retain both responses', async () => {
  const lookup = fakeFetch({
    [keyName]: response(keyName, [answer(keyName, 5, aliasName + '.')]),
    [aliasName]: response(aliasName, [answer(aliasName, 16, record)]),
  });
  const result = await lookupDkimKey('example.test', 'demo', lookup);
  assert.equal(result.key.record, record);
  assert.equal(result.key.sources[0].url, lookup.requests[0].url);
  assert.equal(result.key.sources[0].responses.length, 2);
});

test('unrelated answers and non-DKIM TXT records cannot supply a key', async () => {
  const lookup = fakeFetch({ [keyName]: response(keyName, [
    answer(aliasName, 16, record), answer(keyName, 16, 'v=spf1 -all'),
  ]) });
  assert.equal((await lookupDkimKey('example.test', 'demo', lookup)).code, 'dns-not-found');
});

test('an unrelated TXT does not satisfy a CNAME whose target has no key', async () => {
  const lookup = fakeFetch({
    [keyName]: response(keyName, [answer(keyName, 5, aliasName), answer('attacker.test', 16, record)]),
    [aliasName]: response(aliasName),
  });
  assert.equal((await lookupDkimKey('example.test', 'demo', lookup)).code, 'dns-not-found');
  assert.equal(lookup.requests.length, 2);
});

test('revoked keys and DKIM records missing p= remain available for core diagnosis', async () => {
  for (const keyRecord of ['v=DKIM1; p=', 'v=DKIM1; k=rsa']) {
    const lookup = fakeFetch({ [keyName]: response(keyName, [answer(keyName, 16, keyRecord)]) });
    assert.equal((await lookupDkimKey('example.test', 'demo', lookup)).key.record, keyRecord);
  }
});

test('multiple key records and conflicting aliases are rejected rather than combined', async () => {
  for (const answers of [
    [answer(keyName, 16, record), answer(keyName, 16, record + 'ZA==')],
    [answer(keyName, 5, aliasName), answer(keyName, 16, record)],
    [answer(keyName, 5, aliasName), answer(keyName, 5, 'other.provider.test')],
  ]) {
    const lookup = fakeFetch({ [keyName]: response(keyName, answers) });
    assert.equal((await lookupDkimKey('example.test', 'demo', lookup)).code, 'dns-invalid-response');
  }
});

test('malformed quoted TXT is rejected', async () => {
  for (const encoded of ['"v=DKIM1; p=YWJj', '"v=DKIM1; p=YWJj" junk', '"p=\\999"', '"p=\\12"']) {
    const lookup = fakeFetch({ [keyName]: response(keyName, [answer(keyName, 16, encoded)]) });
    assert.equal((await lookupDkimKey('example.test', 'demo', lookup)).code, 'dns-invalid-response', encoded);
  }
});

test('CNAME loops fail in one response and across multiple responses', async () => {
  for (const replies of [
    { [keyName]: response(keyName, [answer(keyName, 5, aliasName), answer(aliasName, 5, keyName)]) },
    {
      [keyName]: response(keyName, [answer(keyName, 5, aliasName)]),
      [aliasName]: response(aliasName, [answer(aliasName, 5, keyName)]),
    },
  ]) {
    const lookup = fakeFetch(replies);
    assert.equal((await lookupDkimKey('example.test', 'demo', lookup)).code, 'dns-invalid-response');
    assert.ok(lookup.requests.length <= 2);
  }
});

test('long alias chains are bounded to five DNS requests', async () => {
  const replies = {};
  let previous = keyName;
  for (let index = 0; index < 9; index++) {
    const next = `alias${index}.provider.test`;
    replies[previous] = response(previous, [answer(previous, 5, next)]);
    previous = next;
  }
  const lookup = fakeFetch(replies);
  assert.equal((await lookupDkimKey('example.test', 'demo', lookup)).code, 'dns-invalid-response');
  assert.ok(lookup.requests.length <= 5);
});

test('a combined answer cannot bypass the alias-hop limit', async () => {
  const answers = [];
  let previous = keyName;
  for (let index = 0; index < 6; index++) {
    const next = `alias${index}.provider.test`;
    answers.push(answer(previous, 5, next));
    previous = next;
  }
  answers.push(answer(previous, 16, record));
  const lookup = fakeFetch({ [keyName]: response(keyName, answers) });
  assert.equal((await lookupDkimKey('example.test', 'demo', lookup)).code, 'dns-invalid-response');
  assert.equal(lookup.requests.length, 1);
});

test('invalid domain, selector and alias names never become arbitrary URLs', async () => {
  const noFetch = async () => assert.fail('Invalid names must not trigger a request');
  for (const [domain, selector] of [
    ['https://attacker.test', 'demo'], ['example.test', '../x'], ['example.test', 'a'.repeat(64)],
    ['example.test', 'demo?other=value'], ['example.test', ''], ['a..test', 'demo'],
  ]) {
    assert.equal((await lookupDkimKey(domain, selector, { fetchImpl: noFetch })).code, 'dns-invalid-response');
  }
  const lookup = fakeFetch({ [keyName]: response(keyName, [answer(keyName, 5, 'https://attacker.test')]) });
  assert.equal((await lookupDkimKey('example.test', 'demo', lookup)).code, 'dns-invalid-response');
  assert.equal(lookup.requests.length, 1);
});

test('NXDOMAIN, empty answers and failed resolution have distinct useful explanations', async () => {
  for (const [status, expected] of [[3, 'dns-not-found'], [0, 'dns-not-found'], [2, 'dns-unavailable']]) {
    const lookup = fakeFetch({ [keyName]: response(keyName, [], status) });
    const result = await lookupDkimKey('example.test', 'demo', lookup);
    assert.equal(result.code, expected);
    assert.match(result.explanation, /DNS/);
    assert.match(result.explanation, /alter|historical|older/i);
  }
});

test('truncated, mismatched, oversized and malformed responses are rejected', async () => {
  const good = response(keyName, [answer(keyName, 16, record)]);
  for (const reply of [
    { ...good, TC: true }, { ...good, Question: [{ name: aliasName, type: 16 }] },
    { ...good, Question: { length: 1 } }, { ...good, Question: [null] },
    { ...good, Answer: 'not a list' }, { ...good, Status: '0' },
    { ...good, Answer: Array(129).fill(answer(keyName, 16, record)) },
    { ...good, Comment: 'a'.repeat(131073) },
    { ...good, Comment: '🙂'.repeat(35000) },
  ]) {
    const lookup = fakeFetch({ [keyName]: reply });
    assert.equal((await lookupDkimKey('example.test', 'demo', lookup)).code, 'dns-invalid-response');
  }
  const fetchImpl = async () => new Response('not JSON');
  assert.equal((await lookupDkimKey('example.test', 'demo', { fetchImpl })).code, 'dns-invalid-response');
});

test('HTTP and network failures are unable-to-check outcomes', async () => {
  for (const fetchImpl of [
    async () => new Response('', { status: 503 }),
    async () => { throw new TypeError('Failed to fetch'); },
  ]) {
    const result = await lookupDkimKey('example.test', 'demo', { fetchImpl });
    assert.equal(result.code, 'dns-unavailable');
    assert.match(result.explanation, /DNS/);
  }
});

function waitingFetch(url, { signal }) {
  return new Promise((resolve, reject) => signal.addEventListener('abort', () => reject(signal.reason), { once: true }));
}

test('a stalled DNS request times out', async () => {
  const result = await lookupDkimKey('example.test', 'demo', { fetchImpl: waitingFetch, timeoutMs: 5 });
  assert.equal(result.code, 'dns-unavailable');
  assert.match(result.explanation, /too long|timed out/);
});

test('caller cancellation aborts pending work and skips requests if already cancelled', async () => {
  const controller = new AbortController();
  const pending = lookupDkimKey('example.test', 'demo', { fetchImpl: waitingFetch, signal: controller.signal });
  controller.abort();
  assert.equal((await pending).code, 'dns-aborted');
  const fetchImpl = async () => assert.fail('Already aborted lookup must not fetch');
  assert.equal((await lookupDkimKey('example.test', 'demo', { fetchImpl, signal: controller.signal })).code, 'dns-aborted');
});
