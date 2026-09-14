import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { pathToFileURL } from 'node:url';

const project = new URL('../', import.meta.url);
const archive = 'https://archive.zk.email/api/key';
const provenance = 'https://github.com/zkemail/archive/blob/aeff0fa5002d0e3b5f51d3edb54ec8c15cc575a0/docs/signed-observations.md';
export const providers = [
  { name: 'Google / Gmail', domains: ['gmail.com', 'googlemail.com', 'google.com', '1e100.net'] },
  { name: 'Microsoft / Outlook', domains: ['outlook.com', 'hotmail.com', 'live.com', 'microsoft.com'] },
  { name: 'Yahoo / AOL', domains: ['yahoo.com', 'ymail.com', 'aol.com'] },
  { name: 'Apple iCloud', domains: ['icloud.com', 'me.com', 'mac.com'] },
  { name: 'Proton', domains: ['proton.me', 'protonmail.com', 'protonmail.ch', 'pm.me'] },
  { name: 'Fastmail', domains: ['fastmail.com', 'messagingengine.com'] },
  { name: 'Zoho', domains: ['zoho.com', 'zohomail.com'] },
  { name: 'GMX / Web.de', domains: ['gmx.com', 'gmx.net', 'web.de'] },
  { name: 'Yandex', domains: ['yandex.ru', 'yandex.com'] },
  { name: 'Mail.ru', domains: ['mail.ru', 'inbox.ru', 'bk.ru', 'list.ru'] },
  { name: 'Tencent QQ', domains: ['qq.com', 'foxmail.com'] },
  { name: 'NetEase', domains: ['163.com', '126.com'] },
  { name: 'Amazon SES', domains: ['amazonses.com'] },
  { name: 'SendGrid', domains: ['sendgrid.net'] },
  { name: 'Mailgun', domains: ['mailgun.org'] },
  { name: 'Mailchimp Transactional', domains: ['mandrillapp.com'] },
];

const digest = text => createHash('sha256').update(text).digest('hex');
const identity = key => JSON.stringify([key.domain, key.selector, key.record, key.id]);
const keyValue = record => /(?:^|;)\s*p\s*=([^;]*)/.exec(record)?.[1].replace(/\s/g, '');

function summary(keys) {
  const dates = source => keys.flatMap(key => key.sources.flatMap(citation =>
    citation.observations.filter(item => item.source === source).map(item => item.firstSeenAt)
  )).filter(Boolean).sort();
  return {
    recordCount: keys.length,
    keyCount: keys.filter(key => Boolean(keyValue(key.record))).length,
    revocationCount: keys.filter(key => keyValue(key.record) === '').length,
    dnsFirstSeenAt: dates('live_dns')[0] ?? null,
    recoveredFirstSeenAt: dates('gcd_recovered')[0] ?? null,
  };
}

export function buildRegistry(snapshots, retrievedAt, previous = { keys: [] }) {
  const entries = new Map(previous.keys.map(key => [identity(key), structuredClone(key)]));
  for (const snapshot of snapshots) {
    const records = JSON.parse(snapshot.text);
    if (!Array.isArray(records)) throw new Error(`${snapshot.domain}: expected an archive array`);
    for (const record of records) {
      if (record.domain !== snapshot.domain || typeof record.selector !== 'string' ||
          typeof record.value !== 'string' || !Number.isInteger(record.id) || !Array.isArray(record.observations)) {
        throw new Error(`${snapshot.domain}: malformed record or wrong domain`);
      }
      const channels = [...new Set(record.observations.map(item => item.source))];
      const source = {
        label: 'ZK Email DKIM Archive',
        url: `${archive}?domain=${encodeURIComponent(record.domain)}&selector=${encodeURIComponent(record.selector)}`,
        archiveId: record.id, retrievedAt: snapshot.retrievedAt,
        type: channels.length > 1 ? 'mixed' : channels[0] ?? 'unknown',
        observations: record.observations,
        snapshot: snapshot.filename, snapshotSha256: digest(snapshot.text),
      };
      const key = { id: `zkemail:${record.id}`, domain: record.domain,
        selector: record.selector, record: record.value, sources: [source] };
      const prior = entries.get(identity(key));
      if (prior) key.sources = [...prior.sources.filter(item => item.snapshot !== source.snapshot), source];
      entries.set(identity(key), key);
    }
  }
  const keys = [...entries.values()].sort((left, right) =>
    identity(left).localeCompare(identity(right), 'en'));
  return {
    schemaVersion: 1, retrievedAt,
    coverage: {
      complete: false, requestedSince: '2021-09-11',
      note: 'This collection is not complete for all providers or the past five years. Observation dates are evidence dates, not guaranteed key validity intervals.',
      provenance,
    },
    providers: providers.map(provider => {
      const matching = keys.filter(key => provider.domains.includes(key.domain));
      return { ...provider, ...summary(matching),
        domainCoverage: provider.domains.map(domain => ({ domain,
          ...summary(matching.filter(key => key.domain === domain)) })) };
    }),
    snapshots: snapshots.map(({ text, filename, ...metadata }) => ({
      ...metadata, snapshot: filename, snapshotSha256: digest(text),
    })),
    keys,
  };
}

function coverageMarkdown(registry) {
  const rows = registry.providers.flatMap(provider => provider.domainCoverage.map(domain =>
    `| ${provider.name} | ${domain.domain} | ${domain.keyCount} | ${domain.revocationCount} | ${domain.dnsFirstSeenAt?.slice(0, 10) ?? '—'} | ${domain.recoveredFirstSeenAt?.slice(0, 10) ?? '—'} |`));
  return `# Bundled key coverage\n\nRetrieved: ${registry.retrievedAt}. Requested history starts 2021-09-11.\n\n` +
    `**Coverage is not complete.** These are the available archive records for the explicit domains below, including older records. This is not every key used by every major provider since 2021-09-11. Customer-owned domains, regional domains, missing selectors, and unarchived rotations are not covered. A missing key means the message cannot be checked with this bundle.\n\n` +
    `Each record in [keys.json](keys.json) links its exact domain/selector lookup, archive record ID, and an untouched local JSON response with its SHA-256 digest. Public DNS keys are public factual data. The source is the [ZK Email DKIM Archive](https://archive.zk.email/); its [provenance documentation](${provenance}) explains the distinctions below.\n\n` +
    `- DNS dates: the archive reports observing that TXT value in DNS. These are the archive's claims, not independently timestamped proofs, and the first/last observations do not prove uninterrupted publication.\n` +
    `- Recovered dates: dates on submitted email signatures used to reconstruct a key. The archive does not authenticate those submissions. Recovery alone does not establish that the domain published the key or sent the messages.\n` +
    `- An empty public-key field (\`p=\`) records revocation. Retaining an older key permits a mathematical check but does not override revocation or prove historical authorization.\n` +
    `- Selector names containing years are names, not evidence of when keys were used. Earliest dates below describe any record for that domain; they do not establish five-year coverage for every key.\n\n` +
    `Nonempty-key counts include historical weak keys. In this snapshot, \`qq.com\` selector \`s0907\` has a 768-bit RSA key, which must not be accepted for DKIM verification. It is retained so the source history remains auditable.\n\n` +
    `| Provider | Exact signing domain | Nonempty keys | Revocations | Earliest reported DNS observation | Earliest recovered message date |\n` +
    `| --- | --- | ---: | ---: | --- | --- |\n${rows.join('\n')}\n\n` +
    `Refresh from this directory with \`node scripts/update-keys.mjs 2>&1 | tee /tmp/dkim-keys-refresh.log\`. Node 20+ is required. The script queries public domain names only, paces requests to respect the archive's ten-per-minute allowance, retains previously bundled keys, and saves new timestamped source snapshots. It does not read any email files. Review the changes and run \`npm test\` before serving an updated bundle.\n`;
}

async function download(url) {
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const response = await fetch(url, { signal: AbortSignal.timeout(30000) });
    if (response.status === 429) {
      const seconds = Number(response.headers.get('retry-after') ?? 10);
      if (!Number.isFinite(seconds) || seconds < 0 || seconds > 60) {
        throw new Error(`Archive requests a longer delay; retry the refresh later: ${url}`);
      }
      console.log(`Rate limited; waiting ${seconds + 1} seconds`);
      await delay((seconds + 1) * 1000);
      continue;
    }
    if (!response.ok) throw new Error(`HTTP ${response.status}: ${url}`);
    return response.text();
  }
  throw new Error(`Rate limit persisted: ${url}`);
}

async function main() {
  const retrievedAt = new Date().toISOString();
  const directory = `sources/${retrievedAt.replace(/[:.]/g, '-')}`;
  await mkdir(new URL(`${directory}/`, project), { recursive: true });
  let previous = { keys: [] };
  try { previous = JSON.parse(await readFile(new URL('keys.json', project), 'utf8')); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  const snapshots = [];
  for (const domain of providers.flatMap(provider => provider.domains)) {
    if (snapshots.length) await delay(6200);
    const url = `${archive}?domain=${encodeURIComponent(domain)}`;
    const text = await download(url);
    const snapshot = { domain, url, filename: `${directory}/${domain}.json`,
      retrievedAt: new Date().toISOString(), text };
    buildRegistry([snapshot], retrievedAt);
    await writeFile(new URL(snapshot.filename, project), text);
    snapshots.push(snapshot);
    console.log(`${domain}: ${JSON.parse(text).length} archive records`);
  }
  const registry = buildRegistry(snapshots, retrievedAt, previous);
  await writeFile(new URL('keys.json', project), `${JSON.stringify(registry, null, 2)}\n`);
  await writeFile(new URL('COVERAGE.md', project), coverageMarkdown(registry));
  console.log(`Saved ${registry.keys.length} records for ${snapshots.length} domains; coverage remains incomplete.`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
}
