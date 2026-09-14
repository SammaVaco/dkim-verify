import { verifyWithDns } from './verify-with-dns.js';
import { keyProvenance, senderSummary } from './sender.js';

export { keyProvenance } from './sender.js';

const MAX_BYTES = 20 * 1024 * 1024;

export function safeCitation(value, snapshot = false) {
  if (typeof value !== 'string') return null;
  if (snapshot) {
    return /^sources\/[a-zA-Z0-9._/-]+\.json$/.test(value) && !value.includes('..') ? value : null;
  }
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'https:' && !parsed.username && !parsed.password ? parsed.href : null;
  } catch {
    return null;
  }
}

export function suppliedKey(domain, selector, record, citation) {
  if (![domain, selector, record, citation].some(value => value.trim())) return null;
  domain = domain.trim().toLowerCase();
  selector = selector.trim().toLowerCase();
  if (!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(domain) || !domain.includes('.')) {
    throw new Error('Enter the signing domain for the supplied key.');
  }
  if (!/^[a-z0-9_.-]+$/.test(selector) || !record.trim()) {
    throw new Error('Enter the key name and the complete public DNS TXT record.');
  }
  if (citation.trim() && !safeCitation(citation.trim())) throw new Error('The source link must use HTTPS.');
  return { domain, selector, record: record.trim(), sources: [{ type: 'manual', label: 'Key supplied for this check', url: citation.trim(), observations: [] }] };
}

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function addLink(parent, label, url, snapshot = false) {
  const safe = safeCitation(url, snapshot);
  if (!safe) return;
  const link = element('a', label);
  link.href = safe;
  link.target = '_blank';
  link.rel = 'noopener noreferrer';
  parent.append(link);
}

function dateLabel(timestamp) {
  if (timestamp === undefined || timestamp === null) return 'Not specified';
  const date = new Date(typeof timestamp === 'number' ? timestamp * 1000 : timestamp);
  return Number.isNaN(date.getTime()) ? 'Unknown' : date.toISOString().replace('T', ' ').replace('.000Z', ' UTC');
}

function detailRow(list, label, value) {
  list.append(element('dt', label), element('dd', value));
}

function renderKey(key, fingerprint, matched = true) {
  const details = element('details');
  details.open = true;
  details.append(element('summary', matched ? 'Public key and its evidence' : 'Public key retrieved from DNS (not a verified match)'));
  const publicKey = /(?:^|;)\s*p\s*=([^;]*)/i.exec(key.record)?.[1]?.replace(/\s/g, '');
  details.append(element('h3', 'Exact public key (base64)'), element('pre', publicKey ?? 'No public key in this record'));
  if (fingerprint) details.append(element('p', `SHA-256 fingerprint: ${fingerprint}`, 'meta'));
  details.append(element('h3', `${key.selector}._domainkey.${key.domain} — full TXT record`), element('pre', key.record));
  for (const source of key.sources ?? []) {
    const paragraph = element('p', `${source.label ?? 'Public key archive'}${source.archiveId ? ` · record ${source.archiveId}` : ''} `);
    addLink(paragraph, 'Original source', source.url);
    if (source.snapshot) {
      paragraph.append(document.createTextNode(' · '));
      addLink(paragraph, 'Saved evidence', source.snapshot, true);
    }
    if (!source.url && !source.snapshot) paragraph.append(document.createTextNode('No independent citation supplied.'));
    details.append(paragraph);
    if (source.retrievedAt) details.append(element('p', `Retrieved: ${dateLabel(source.retrievedAt)}`, 'meta'));
    if (source.snapshotSha256) details.append(element('p', `Saved response SHA-256: ${source.snapshotSha256}`, 'meta'));
    for (const observation of source.observations ?? []) {
      const channel = observation.source === 'live_dns' ? 'DNS observation' : 'Recovered from message signatures (not DNS evidence)';
      details.append(element('p', `${channel}: ${dateLabel(observation.firstSeenAt)} — ${dateLabel(observation.lastSeenAt)}`, 'meta'));
    }
    if (source.responses) {
      const evidence = element('details');
      evidence.append(element('summary', 'DNS responses used for this check'));
      for (const lookup of source.responses) {
        const citation = element('p');
        addLink(citation, 'DNS lookup', lookup.url);
        evidence.append(citation, element('pre', JSON.stringify(lookup.response, null, 2)));
      }
      details.append(evidence);
    }
  }
  return details;
}

function renderSignature(result, index) {
  const provenance = keyProvenance(result.key);
  const unconfirmed = result.status === 'valid' && provenance.kind !== 'dns';
  const card = element('article', undefined, `result ${unconfirmed ? 'uncertain' : result.status}`);
  const titles = { valid: provenance.origin === 'live' ? 'Signature valid against a key from current DNS' : 'Signature valid against an archived DNS key', invalid: 'Signature does not validate', unverifiable: 'Unable to verify this signature', expired: 'Signature has expired' };
  card.append(element('h2', `${index + 1}. ${unconfirmed ? 'Signature matches; domain ownership unconfirmed' : titles[result.status] ?? 'Unable to verify'}`));
  card.append(element('p', result.explanation));
  if (result.key) card.append(element('p', provenance.explanation, provenance.kind === 'dns' ? 'meta' : 'warning'));
  if (result.dnsLookup?.key) card.append(element('p', 'Current DNS key: the key was absent from the local collection, so it was looked up online. The email itself was not sent.', 'meta'));
  const facts = element('dl');
  if (result.domain) detailRow(facts, 'Signing domain', result.domain);
  if (result.selector) detailRow(facts, 'Key name', result.selector);
  if (result.algorithm) detailRow(facts, 'Algorithm', result.algorithm);
  if (result.signedHeaders) detailRow(facts, 'Signed headers', result.signedHeaders.join(', '));
  if (result.bodyHashMatches !== undefined) detailRow(facts, 'Signed body matches', result.bodyHashMatches ? 'Yes' : 'No');
  if (result.signatureMatches !== undefined) detailRow(facts, 'Header signature matches', result.signatureMatches ? 'Yes' : 'No');
  if (result.signingTime !== undefined) detailRow(facts, 'Claimed signing time', dateLabel(result.signingTime));
  if (result.expiresAt !== undefined) detailRow(facts, 'Expiration', dateLabel(result.expiresAt));
  detailRow(facts, 'Diagnostic', result.code ?? result.status);
  card.append(facts);
  for (const warning of result.warnings ?? []) card.append(element('p', warning, 'warning'));
  if (result.key) card.append(renderKey(result.key, result.keyFingerprint));
  else if (result.dnsLookup?.key) card.append(renderKey(result.dnsLookup.key, undefined, false));
  return card;
}

function renderReport(report, historicalTime) {
  const summary = senderSummary(report);
  const verdict = element('article', undefined, `panel sender-verdict ${summary.status}`);
  verdict.id = 'sender-verdict';
  verdict.append(element('p', 'Does the signature support the From address?', 'eyebrow'), element('h2', summary.title));
  if (summary.address) verdict.append(element('p', `From: ${summary.address}`, 'sender-address'));
  verdict.append(element('p', summary.explanation));
  if (historicalTime !== undefined) verdict.append(element('p', `Checked at the receipt time you supplied: ${dateLabel(historicalTime)}. This uses your chosen time rather than the current clock.`, 'warning'));
  for (const note of summary.notes) verdict.append(element('p', note, summary.status === 'limited' ? 'warning' : 'meta'));
  const technical = element('details');
  technical.id = 'technical-details';
  technical.append(element('summary', 'More information'));
  report.signatures.forEach((result, index) => technical.append(renderSignature(result, index)));
  return [verdict, technical];
}

function renderCoverage(catalogue) {
  document.querySelector('#catalogue-summary').textContent = `${catalogue.keys.length} records bundled. Retrieved ${dateLabel(catalogue.retrievedAt)}. Missing keys can be looked up in current DNS if enabled. If still unavailable, the result is “unable to verify,” not a claim of tampering.`;
  const rows = document.querySelector('#coverage-rows');
  for (const provider of catalogue.providers ?? []) {
    const keys = catalogue.keys.filter(key => provider.domains.includes(key.domain));
    const dates = keys.flatMap(key => key.sources.flatMap(source => source.observations ?? []))
      .filter(observation => observation.source === 'live_dns' && observation.firstSeenAt)
      .map(observation => observation.firstSeenAt).sort();
    const row = element('tr');
    [provider.name, provider.domains.join(', '), String(keys.length), dates.length ? dates[0].slice(0, 10) : 'No DNS evidence bundled']
      .forEach(value => row.append(element('td', value)));
    rows.append(row);
  }
}

async function start() {
  const form = document.querySelector('#verify-form');
  const fileInput = document.querySelector('#email-file');
  const textInput = document.querySelector('#email-text');
  const status = document.querySelector('#input-status');
  const results = document.querySelector('#results');
  const button = document.querySelector('#verify-button');
  let catalogue;
  let runNumber = 0;
  let activeCheck;

  try {
    if (!globalThis.crypto?.subtle) {
      throw new Error(globalThis.isSecureContext
        ? 'This browser does not provide Web Crypto. Try a current browser.'
        : 'Your browser disables Web Crypto on this HTTP address. Use http://localhost through a host port-forward, or serve the page over trusted HTTPS. Changing only the URL to https:// will not work. See the setup instructions in README.md.');
    }
    const response = await fetch('./keys.json', { credentials: 'omit' });
    if (!response.ok) throw new Error('Could not load the bundled public keys. Reload the page or check that keys.json was deployed.');
    catalogue = await response.json();
    if (catalogue.schemaVersion !== 1 || !Array.isArray(catalogue.keys)) throw new Error('The bundled key catalogue has an unsupported format.');
    catalogue.keys.sort((left, right) => Number(keyProvenance(right).kind === 'dns') - Number(keyProvenance(left).kind === 'dns'));
    renderCoverage(catalogue);
    status.textContent = 'Ready. Verification runs locally.';
    button.disabled = false;
  } catch (error) {
    status.textContent = error.message;
    status.className = 'error';
    return;
  }

  fileInput.addEventListener('change', () => {
    if (fileInput.files.length) textInput.value = '';
    results.replaceChildren();
    status.textContent = fileInput.files[0] ? `Selected ${fileInput.files[0].name}. File contents stay local.` : 'Ready.';
  });
  textInput.addEventListener('input', () => {
    fileInput.value = '';
    results.replaceChildren();
  });
  form.addEventListener('input', () => {
    activeCheck?.abort();
    runNumber += 1;
    button.disabled = false;
    results.replaceChildren();
    status.textContent = 'Input changed. Check signatures to see updated results.';
    status.className = '';
  });
  form.addEventListener('reset', () => {
    activeCheck?.abort();
    runNumber += 1;
    button.disabled = false;
    results.replaceChildren();
    status.textContent = 'Cleared. No email is stored by this app.';
    status.className = '';
  });
  form.addEventListener('submit', async event => {
    event.preventDefault();
    activeCheck?.abort();
    const controller = new AbortController();
    activeCheck = controller;
    const thisRun = ++runNumber;
    results.replaceChildren();
    status.className = '';
    button.disabled = true;
    try {
      const file = fileInput.files[0];
      if (file?.size > MAX_BYTES || textInput.value.length > MAX_BYTES) throw new Error('This email exceeds the 20 MiB limit.');
      const bytes = file ? new Uint8Array(await file.arrayBuffer()) : new TextEncoder().encode(textInput.value);
      if (thisRun !== runNumber || controller.signal.aborted) return;
      if (!bytes.length) throw new Error('Upload an .eml file or paste its complete contents first.');
      if (bytes.length > MAX_BYTES) throw new Error('This email exceeds the 20 MiB limit.');
      const extra = suppliedKey(...['key-domain', 'key-selector', 'key-record', 'key-citation'].map(id => document.getElementById(id).value));
      const historicalDate = document.querySelector('#verify-date').value;
      const now = historicalDate ? Date.parse(`${historicalDate}Z`) / 1000 : Math.floor(Date.now() / 1000);
      if (!Number.isFinite(now)) throw new Error('Enter a valid verification date in UTC.');
      const dnsFallback = document.querySelector('#dns-fallback').checked;
      status.textContent = dnsFallback ? 'Checking locally; looking up missing keys in DNS if needed…' : 'Checking signatures locally; DNS lookup is off…';
      const report = await verifyWithDns(bytes, extra ? [...catalogue.keys, extra] : catalogue.keys, { now, dnsFallback, signal: controller.signal });
      if (thisRun !== runNumber) return;
      results.append(...renderReport(report, historicalDate ? now : undefined));
      status.textContent = `Check complete at ${dateLabel(now)}${historicalDate ? ' (time supplied by you)' : ''}. ${file ? 'Original file bytes used.' : 'Pasted text interpreted as UTF-8; upload the original if verification fails.'}`;
    } catch (error) {
      if (thisRun === runNumber) {
        status.textContent = error.message || 'The check could not complete in this browser.';
        status.className = 'error';
      }
    } finally {
      if (thisRun === runNumber) button.disabled = false;
    }
  });
}

if (typeof document !== 'undefined') start();
