import { verifyEmail } from './dkim.js';
import { lookupDkimKey } from './dns.js';

const MAX_LOOKUPS = 10;
const keyName = signature => `${signature.selector}._domainkey.${signature.domain}`;

export async function verifyWithDns(bytes, keys, options = {}) {
  const local = await verifyEmail(bytes, keys, options);
  if (!options.dnsFallback || options.signal?.aborted) return local;
  const missing = new Map(local.signatures.filter(result => result.code === 'missing-key')
    .map(result => [keyName(result), result]));
  if (!missing.size) return local;

  const lookups = new Map();
  const pending = [...missing].slice(0, MAX_LOOKUPS);
  await Promise.all(pending.map(async ([name, result]) => {
    lookups.set(name, await lookupDkimKey(result.domain, result.selector, options));
  }));
  if (options.signal?.aborted) return local;

  const fetched = [...lookups.values()].flatMap(outcome => outcome.key ? [outcome.key] : []);
  const report = fetched.length ? await verifyEmail(bytes, [...keys, ...fetched], options) : local;
  report.signatures.forEach((result, index) => {
    if (local.signatures[index].code !== 'missing-key') return;
    const outcome = lookups.get(keyName(result));
    if (!outcome) {
      result.code = 'dns-limit';
      result.explanation = `This email needs more than ${MAX_LOOKUPS} different DNS key lookups. Additional lookups were skipped to limit network requests. You can supply a missing key manually; this is not evidence of alteration.`;
      return;
    }
    result.dnsLookup = outcome;
    if (!outcome.key) Object.assign(result, { status: 'unverifiable', code: outcome.code, explanation: outcome.explanation });
  });
  return report;
}
