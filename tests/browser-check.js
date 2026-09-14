export default async function checkBrowser(page) {
  const check = (condition, message) => { if (!condition) throw new Error(message); };
  const base = new URL(page.url()).origin;
  const fixtures = await (await page.request.get(`${base}/tests/fixtures/vectors.json`)).json();
  const original = Buffer.from(fixtures.messages['rsa-relaxed-relaxed'], 'base64');
  const browserErrors = [];
  page.on('pageerror', error => browserErrors.push(error.message));
  const keyName = `${fixtures.keys[0].selector}._domainkey.${fixtures.keys[0].domain}`;
  const aliasName = 'rsa._domainkey.alias.example.test';
  let dnsResponse = 'key';
  let delayedDns;
  await page.route('https://dns.google/**', async route => {
    const name = new URL(route.request().url()).searchParams.get('name');
    check([keyName, aliasName].includes(name), `Unexpected DNS question: ${name}`);
    const Answer = name === keyName
      ? [{ name, type: 5, TTL: 60, data: `${aliasName}.` }]
      : [{ name, type: 16, TTL: 60, data: [fixtures.keys[0].record.slice(0, 150), fixtures.keys[0].record.slice(150)].map(chunk => JSON.stringify(chunk)).join('') }];
    const delayed = delayedDns;
    delayedDns = undefined;
    if (delayed) {
      delayed.started();
      await delayed.response;
    }
    await route.fulfill({ json: { Status: dnsResponse === 'missing' ? 3 : 0, Question: [{ name, type: 16 }], Answer: dnsResponse === 'missing' ? [] : Answer } });
    delayed?.finished();
  });
  await page.goto(base);
  await page.waitForFunction(() => !document.querySelector('#verify-button').disabled);
  await page.waitForLoadState('networkidle');
  check(await page.locator('#dns-fallback').count() === 1, 'The DNS fallback needs a visible opt-out');
  check(await page.locator('#dns-fallback').isChecked(), 'Missing-key DNS fallback must be enabled by default');
  await page.locator('#dns-fallback').uncheck();
  const requests = [];
  const recordRequest = request => requests.push(request);
  const requestUrls = () => requests.map(request => request.url()).join(', ');
  page.on('request', recordRequest);

  const checkDnsRequests = expectedNames => {
    check(requests.length === expectedNames.length, `Unexpected DNS requests: ${requestUrls()}`);
    requests.forEach((request, index) => {
      const url = new URL(request.url());
      check(url.origin === 'https://dns.google' && url.pathname === '/resolve', 'Only the disclosed DNS resolver may receive requests');
      check(url.searchParams.get('name') === expectedNames[index], 'DNS requests must contain only the signature key name or its DNS alias');
      check(url.searchParams.get('type') === 'TXT', 'Only TXT records should be requested');
      check(url.searchParams.get('edns_client_subnet') === '0.0.0.0/0', 'DNS requests must disable forwarding client subnets');
      check([...url.searchParams].length === 3, 'DNS requests must not include email data in extra parameters');
      check(request.method() === 'GET' && request.postData() === null, 'Email bytes must not be uploaded');
      check(!request.headers().referer && !request.headers().cookie, 'DNS requests must omit referrers and cookies');
    });
  };

  let senderTitle;
  let senderText;
  const checkSender = (title, address = 'alice@example.test') => {
    check(senderTitle === title, `Unexpected sender verdict: ${senderTitle}`);
    check(senderText.includes(address), `The sender verdict must show the actual mailbox ${address}`);
  };
  const submit = async () => {
    await page.getByRole('button', { name: 'Check signatures' }).click();
    await page.locator('#results .result').first().waitFor({ state: 'attached' });
    check((await page.locator('#input-status').textContent()).includes('Check complete'), 'The UI did not finish verification');
    const verdict = page.locator('#sender-verdict');
    check(await verdict.count() === 1 && await verdict.isVisible(), 'A visible sender verdict must precede technical details');
    check(await page.locator('#results').evaluate(element => element.firstElementChild.id) === 'sender-verdict', 'The sender verdict must be the first result');
    check(!await page.locator('#technical-details').evaluate(element => element.open), 'Technical information must start collapsed for every check');
    check(!await page.locator('#results .result').first().isVisible(), 'Signature diagnostics must initially be hidden');
    check(await page.locator('#results pre:visible, #results a:visible').count() === 0, 'Public keys and source citations must start inside the collapsed details');
    senderTitle = await verdict.locator('h2').innerText();
    senderText = await verdict.innerText();
    check(!/rsa-sha256|ed25519-sha256|SHA-256 fingerprint:|CRLF/.test(senderText), 'The initial sender verdict must not contain technical diagnostics');
    if (senderTitle === 'Sender domain confirmed') {
      check(/not|cannot/i.test(senderText) && /mailbox|account|person/i.test(senderText), 'A positive verdict must visibly disclaim proof of the exact account or person');
    }
    await page.getByText('More information', { exact: true }).click();
    check(await page.locator('#results .result').first().isVisible(), 'More information must reveal the signature reports');
    return page.locator('#results').innerText();
  };
  const upload = async bytes => {
    await page.locator('#email-file').setInputFiles({ name: 'synthetic.eml', mimeType: 'message/rfc822', buffer: bytes });
    return submit();
  };

  check((await upload(original)).includes('No local public key'), 'Missing keys must be distinguished from altered mail');
  checkSender('Sender not confirmed');
  await page.getByText('Historical checks or a missing public key', { exact: true }).click();
  await page.locator('#key-domain').fill(fixtures.keys[0].domain);
  await page.locator('#key-selector').fill(fixtures.keys[0].selector);
  await page.locator('#key-record').fill(fixtures.keys[0].record);
  await page.locator('#key-citation').fill('https://example.test/synthetic-fixture');
  let report = await submit();
  checkSender('Sender not confirmed');
  check(/key|evidence/i.test(senderText), 'The sender verdict must explain missing key provenance');
  check(report.includes('Signature matches; domain ownership unconfirmed'), 'A supplied key must not authenticate domain ownership');
  check(report.includes(fixtures.keys[0].record), 'The exact public key must be shown');
  check(await page.getByRole('link', { name: 'Original source', exact: true }).getAttribute('href') === 'https://example.test/synthetic-fixture', 'The citation must be shown');

  const changedHeader = Buffer.from(original.toString('latin1').replace('alice@example.test', 'mallory@example.test'), 'latin1');
  check(!changedHeader.equals(original), 'The test must actually change the From address');
  check((await upload(changedHeader)).includes('signature-mismatch'), 'Changed From must fail with an explanation');
  checkSender('Sender not confirmed', 'mallory@example.test');
  const changedBody = Buffer.from(original);
  changedBody[changedBody.indexOf('\r\n\r\n') + 4] ^= 1;
  check((await upload(changedBody)).includes('body-mismatch'), 'Changed body must produce a distinct explanation');
  checkSender('Sender not confirmed');

  await page.locator('#email-text').fill(Buffer.from(fixtures.messages['empty-simple'], 'base64').toString('utf8'));
  check((await submit()).includes('Signature matches; domain ownership unconfirmed'), 'Pasted raw ASCII mail must verify');
  check(await page.locator('#email-file').evaluate(input => input.files.length) === 0, 'Pasting must clear the selected file');
  await page.locator('#email-text').fill('From: <img src="https://invalid.example/tracker">\n\n<img src="https://invalid.example/tracker">');
  check((await submit()).includes('no-signature'), 'Unsigned email needs a clear explanation');
  check(await page.locator('img').count() === 0, 'Email markup must never become live HTML');
  check(requests.length === 0, `Disabled DNS fallback made network requests: ${requestUrls()}`);

  page.off('request', recordRequest);
  await page.reload();
  await page.waitForFunction(() => !document.querySelector('#verify-button').disabled);
  await page.waitForLoadState('networkidle');
  check(await page.locator('#dns-fallback').isChecked(), 'Reloading must restore the disclosed DNS default');
  requests.length = 0;
  page.on('request', recordRequest);
  report = await upload(original);
  checkSender('Sender domain confirmed');
  check(report.includes('Signature valid against a key from current DNS'), 'A missing key supplied by DNS must validate locally');
  check(/current DNS/i.test(senderText), 'The primary verdict must identify current DNS evidence');
  check(report.includes('Current DNS key'), 'Current DNS evidence must be distinguished from the archive');
  check(report.includes(fixtures.keys[0].record), 'The exact DNS TXT record must be shown');
  check(report.includes('SHA-256 fingerprint:') && report.includes('Retrieved:'), 'A current DNS key needs its fingerprint and retrieval time');
  checkDnsRequests([keyName, aliasName]);
  check(await page.getByRole('link', { name: 'Original source', exact: true }).first().getAttribute('href') === requests[0].url(), 'The original DNS lookup needs an auditable citation');
  check((await page.locator('#results').textContent()).includes(aliasName), 'The DNS alias must remain available in the response evidence');

  requests.length = 0;
  check((await upload(changedHeader)).includes('signature-mismatch'), 'A key fetched from DNS must still reject changed signed headers');
  checkSender('Sender not confirmed', 'mallory@example.test');
  checkDnsRequests([keyName, aliasName]);
  dnsResponse = 'missing';
  requests.length = 0;
  report = await upload(original);
  checkSender('Sender not confirmed');
  check(report.includes('Unable to verify') && report.includes('DNS'), 'Missing DNS records need a comprehensible explanation');
  check(await page.locator('#results .result.invalid').count() === 0, 'Missing DNS records must not imply the email was altered');
  checkDnsRequests([keyName]);

  dnsResponse = 'key';
  for (const action of ['clear', 'edit']) {
    let started;
    let release;
    let finished;
    const lookupStarted = new Promise(resolve => { started = resolve; });
    const response = new Promise(resolve => { release = resolve; });
    const lookupFinished = new Promise(resolve => { finished = resolve; });
    delayedDns = { started, response, finished };
    requests.length = 0;
    await page.locator('#email-file').setInputFiles({ name: 'synthetic.eml', mimeType: 'message/rfc822', buffer: original });
    const lookupAborted = page.waitForEvent('requestfailed', {
      predicate: request => request.url().startsWith('https://dns.google/'), timeout: 2000,
    });
    await page.getByRole('button', { name: 'Check signatures' }).click();
    await lookupStarted;
    if (action === 'clear') await page.locator('#clear-button').click();
    else await page.locator('#email-text').fill('From: replacement@example.test\n\nReplacement email');
    try {
      const failed = await lookupAborted;
      check(/abort|cancel/i.test(failed.failure().errorText), `${action} must abort the in-flight DNS request`);
    } finally {
      release();
    }
    await lookupFinished;
    await page.waitForLoadState('networkidle');
    check(await page.locator('#results .result').count() === 0, `${action} must not show late verification results`);
    check(await page.locator('#sender-verdict').count() === 0, `${action} must not leave a stale sender verdict`);
    check((await page.locator('#input-status').textContent()).includes(action === 'clear' ? 'Cleared.' : 'Input changed.'), `${action} status must survive a late response`);
    checkDnsRequests([keyName]);
  }

  requests.length = 0;
  await page.locator('#dns-fallback').uncheck();
  check((await upload(original)).includes('No local public key'), 'Disabling fallback must restore the offline missing-key result');
  check(requests.length === 0, `Opting out still made requests: ${requestUrls()}`);

  await page.locator('#dns-fallback').check();
  await page.evaluate(() => {
    const arrayBuffer = File.prototype.arrayBuffer;
    File.prototype.arrayBuffer = function () {
      File.prototype.arrayBuffer = arrayBuffer;
      return new Promise(resolve => {
        globalThis.releaseFileRead = async () => {
          resolve(await arrayBuffer.call(this));
          delete globalThis.releaseFileRead;
        };
      });
    };
  });
  await page.getByRole('button', { name: 'Check signatures' }).click();
  await page.waitForFunction(() => typeof globalThis.releaseFileRead === 'function');
  await page.locator('#clear-button').click();
  await page.evaluate(() => globalThis.releaseFileRead());
  check((await page.locator('#input-status').textContent()).includes('Cleared.'), 'A stale file read must not overwrite the cleared status');
  check(await page.locator('#results .result').count() === 0, 'A stale file read must not publish a result');
  check(await page.locator('#sender-verdict').count() === 0, 'A stale file read must not publish a sender verdict');
  check(await page.locator('#verify-button').isEnabled(), 'A stale file read must not leave the form disabled');
  check(requests.length === 0, `A cancelled file read made requests: ${requestUrls()}`);

  page.off('request', recordRequest);
  const syntheticCatalogue = {
    schemaVersion: 1, retrievedAt: '2026-01-01T00:00:00Z', providers: [],
    keys: fixtures.keys.map(key => ({ ...key, sources: [{
      label: 'Synthetic test evidence', archiveId: 'synthetic',
      url: 'https://example.test/synthetic-fixture', snapshot: 'sources/synthetic.json',
      observations: [{ source: 'live_dns', firstSeenAt: '2026-01-01T00:00:00Z', lastSeenAt: '2026-01-01T00:00:00Z' }],
    }] })),
  };
  await page.route('**/keys.json', route => route.fulfill({ json: syntheticCatalogue }));
  await page.reload();
  await page.waitForFunction(() => !document.querySelector('#verify-button').disabled);
  await page.waitForLoadState('networkidle');
  check(await page.locator('#dns-fallback').isChecked(), 'Existing registry keys must be tested with DNS fallback enabled');
  requests.length = 0;
  page.on('request', recordRequest);
  report = await upload(original);
  checkSender('Sender domain confirmed');
  check(report.includes('Signature valid against an archived DNS key'), 'A match with DNS evidence needs a valid report');
  check(/archiv/i.test(senderText), 'The primary verdict must identify reliance on archive evidence');
  check(report.includes('SHA-256 fingerprint:'), 'A valid report needs the key fingerprint');
  check(await page.getByRole('link', { name: 'Saved evidence', exact: true }).getAttribute('href') === 'sources/synthetic.json', 'A valid report needs its saved citation');
  await upload(Buffer.from(fixtures.messages['appended-body'], 'base64'));
  checkSender('Sender check has limits');
  check(/part|unsigned/i.test(senderText) && /add|append/i.test(senderText), 'Partial protection and possible appended text must be visible before expansion');
  report = await upload(Buffer.from(fixtures.messages.multiple, 'base64'));
  checkSender('Sender domain confirmed');
  check(await page.locator('#results .result.valid').count() === 2, 'RSA and Ed25519 signatures must both verify in the browser');
  check(report.includes('ed25519-sha256'), 'The Ed25519 signature must be included');
  check((await upload(Buffer.from(fixtures.messages.expires, 'base64'))).includes('Signature has expired'), 'Historical expiry must be explained');
  checkSender('Sender not confirmed');
  check(/expir/i.test(senderText), 'The primary verdict must explain an expired signature');
  await page.getByText('Historical checks or a missing public key', { exact: true }).click();
  await page.locator('#verify-date').fill(new Date(fixtures.verificationTime * 1000).toISOString().slice(0, 16));
  check((await submit()).includes('Signature valid against an archived DNS key'), 'An explicit historical clock must be used');
  checkSender('Sender domain confirmed');
  check(requests.length === 0, `Bundled registry keys caused DNS requests: ${requestUrls()}`);
  check(browserErrors.length === 0, browserErrors.join('\n'));
  check(await page.evaluate(() => localStorage.length + sessionStorage.length) === 0, 'The app must not persist email');
  await page.locator('#results').screenshot({ path: 'output/playwright/result-desktop.png' });
  await page.setViewportSize({ width: 390, height: 844 });
  check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Key evidence must fit a mobile screen');
  await page.locator('#results').screenshot({ path: 'output/playwright/result-mobile.png' });
  page.off('request', recordRequest);
  await page.unroute('**/keys.json');
  await page.unroute('https://dns.google/**');
  await page.goto(base);
  await page.waitForFunction(() => !document.querySelector('#verify-button').disabled);
  return 'PASS: sender-first verdicts, collapsed audit details, partial-body caution, upload/paste, RSA/Ed25519, tampering, citations, expiry, safe rendering, DNS fallback/privacy, cancellation, stale file reads, and offline opt-out';
}
