import assert from 'node:assert/strict';
import test from 'node:test';

import { keyProvenance, safeCitation, suppliedKey } from '../app.js';

test('only DNS observations establish archived domain attribution', () => {
  const recovered = { sources: [{ observations: [{ source: 'gcd_recovered' }] }] };
  assert.equal(keyProvenance(recovered).kind, 'unconfirmed');
  recovered.sources.push({ observations: [{ source: 'live_dns' }] });
  assert.equal(keyProvenance(recovered).kind, 'dns');
  assert.equal(keyProvenance({ sources: [{ type: 'manual' }] }).kind, 'unconfirmed');
});

test('a newly queried DNS key is distinguished from archived evidence', () => {
  const provenance = keyProvenance({ sources: [{ type: 'dns' }] });
  assert.equal(provenance.kind, 'dns');
  assert.equal(provenance.origin, 'live');
  assert.equal(provenance.label, 'Current DNS key');
  assert.match(provenance.explanation, /historical|past/i);
});

test('citations reject executable URLs and snapshot traversal', () => {
  assert.equal(safeCitation('javascript:alert(1)'), null);
  assert.equal(safeCitation('data:text/html,bad'), null);
  assert.equal(safeCitation('https://archive.zk.email/api/key?domain=gmail.com'),
    'https://archive.zk.email/api/key?domain=gmail.com');
  assert.equal(safeCitation('sources/gmail.com.json', true), 'sources/gmail.com.json');
  assert.equal(safeCitation('sources/../../private.json', true), null);
  assert.equal(safeCitation('//untrusted.example/key', true), null);
});

test('supplied keys are scoped and labeled rather than treated as archive evidence', () => {
  assert.equal(suppliedKey('', '', '', ''), null);
  const key = suppliedKey('Example.test', 'demo', 'v=DKIM1; p=YWJj', 'https://example.test/key');
  assert.equal(key.domain, 'example.test');
  assert.equal(keyProvenance(key).kind, 'unconfirmed');
  assert.equal(key.sources[0].url, 'https://example.test/key');
  assert.throws(() => suppliedKey('', 'demo', 'p=YWJj', ''), /domain/i);
  assert.throws(() => suppliedKey('example.test', 'demo', 'p=YWJj', 'javascript:alert(1)'), /https/i);
});
