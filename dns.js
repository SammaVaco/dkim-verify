const resolver = 'https://dns.google/resolve';
const maxSteps = 5;
const maxResponseBytes = 131072;

class DnsResponseError extends Error {}

function outcome(code, explanation) {
  return { code, explanation: `${explanation} This does not show that the email was altered.` };
}

function dnsName(value, allowUnderscores = true) {
  if (typeof value !== 'string') return null;
  const name = value.toLowerCase().replace(/\.$/, '');
  const labelPattern = allowUnderscores
    ? /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/
    : /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
  return name.length <= 253 && name.split('.').every(label => labelPattern.test(label)) ? name : null;
}

function txtRecord(value) {
  if (typeof value !== 'string' || value.length > 65535) {
    throw new DnsResponseError('The DNS answer contains an invalid or oversized TXT record.');
  }
  if (!value.trimStart().startsWith('"')) return value;
  let position = 0;
  let result = '';
  while (position < value.length) {
    while (/\s/.test(value[position] ?? '') && position < value.length) position++;
    if (position === value.length) break;
    if (value[position++] !== '"') throw new DnsResponseError('The DNS TXT record has malformed quoted text.');
    let closed = false;
    while (position < value.length) {
      let character = value[position++];
      if (character === '"') {
        closed = true;
        break;
      }
      if (character === '\\') {
        if (position === value.length) throw new DnsResponseError('The DNS TXT record has an incomplete escape.');
        character = value[position++];
        if (/\d/.test(character)) {
          const decimal = character + value.slice(position, position + 2);
          if (!/^\d{3}$/.test(decimal) || Number(decimal) > 255) {
            throw new DnsResponseError('The DNS TXT record has an invalid escaped character.');
          }
          character = String.fromCharCode(Number(decimal));
          position += 2;
        }
      }
      result += character;
    }
    if (!closed) throw new DnsResponseError('The DNS TXT record has an unclosed quotation mark.');
  }
  return result;
}

function isDkimRecord(record) {
  return /(?:^|;)\s*p\s*=/.test(record) || /^\s*v\s*=\s*DKIM1(?:\s*;|\s*$)/.test(record);
}

async function resolveKey(domain, selector, fetchImpl, signal) {
  let currentName = `${selector}._domainkey.${domain}`;
  const visited = new Set([currentName]);
  const responses = [];
  let aliasCount = 0;
  for (let requestCount = 0; requestCount < maxSteps; requestCount++) {
    signal.throwIfAborted();
    const url = new URL(resolver);
    url.search = new URLSearchParams({ name: currentName, type: 'TXT', edns_client_subnet: '0.0.0.0/0' });
    const fetched = await fetchImpl(url.href, {
      method: 'GET', credentials: 'omit', referrerPolicy: 'no-referrer', redirect: 'error', cache: 'no-store', signal,
    });
    if (!fetched.ok) return outcome('dns-unavailable', 'The DNS service could not answer. Try again later or supply a public key manually.');
    const text = await fetched.text();
    signal.throwIfAborted();
    if (text.length > maxResponseBytes || new TextEncoder().encode(text).length > maxResponseBytes) {
      throw new DnsResponseError('The DNS response was too large to check safely.');
    }
    let response;
    try {
      response = JSON.parse(text);
    } catch {
      throw new DnsResponseError('The DNS service returned unreadable data.');
    }
    responses.push({ url: url.href, response });
    if (!response || !Number.isInteger(response.Status)) throw new DnsResponseError('The DNS response has no valid result status.');
    if (response.Status === 3) return outcome('dns-not-found', 'DNS has no record for this key name. An older email may need a historical public key.');
    if (response.Status !== 0) return outcome('dns-unavailable', 'DNS could not resolve this key name. Try again later or supply a historical public key.');
    if (response.TC || !Array.isArray(response.Question) || response.Question.length !== 1 || response.Question[0]?.type !== 16 ||
        dnsName(response.Question[0].name) !== currentName) {
      throw new DnsResponseError('The DNS response is incomplete or answers a different question.');
    }
    const answers = response.Answer ?? [];
    if (!Array.isArray(answers) || answers.length > 128) throw new DnsResponseError('The DNS response contains an invalid answer list.');
    while (true) {
      const matching = answers.filter(entry => entry && dnsName(entry.name) === currentName);
      const aliases = matching.filter(entry => entry.type === 5);
      const records = matching.filter(entry => entry.type === 16);
      if (aliases.length > 1 || (aliases.length && records.length)) {
        throw new DnsResponseError('DNS returned conflicting records for this key name, so no key can be selected safely.');
      }
      if (aliases.length) {
        const target = dnsName(aliases[0].data);
        if (!target || visited.has(target) || ++aliasCount > maxSteps) {
          throw new DnsResponseError('The DNS aliases contain an invalid name, a loop, or too many steps to follow safely.');
        }
        visited.add(target);
        currentName = target;
        if (answers.some(entry => entry && dnsName(entry.name) === currentName)) continue;
        break;
      }
      const candidates = records.map(entry => txtRecord(entry.data)).filter(isDkimRecord);
      if (candidates.length > 1) throw new DnsResponseError('DNS returned multiple DKIM keys for the same name, so no key can be selected safely.');
      if (!candidates.length) return outcome('dns-not-found', 'DNS has no DKIM public key for this name. An older email may need a historical public key.');
      return { key: {
        domain, selector, record: candidates[0],
        sources: [{ type: 'dns', label: 'Google Public DNS', url: responses[0].url,
          retrievedAt: new Date().toISOString(), responses }],
      } };
    }
  }
  throw new DnsResponseError('The DNS key requires too many lookup steps to follow safely.');
}

export async function lookupDkimKey(domain, selector, { fetchImpl = globalThis.fetch, timeoutMs = 8000, signal } = {}) {
  const signingDomain = dnsName(domain, false);
  const keySelector = dnsName(selector);
  if (!signingDomain?.includes('.') || !keySelector || `${keySelector}._domainkey.${signingDomain}`.length > 253) {
    return outcome('dns-invalid-response', 'The signature does not contain a valid DNS domain and key name.');
  }
  if (signal?.aborted) return outcome('dns-aborted', 'The DNS lookup was cancelled.');
  const controller = new AbortController();
  const cancel = () => controller.abort();
  signal?.addEventListener('abort', cancel, { once: true });
  const timeout = setTimeout(cancel, Math.max(1, Math.min(Number.isFinite(timeoutMs) ? timeoutMs : 8000, 30000)));
  try {
    return await resolveKey(signingDomain, keySelector, fetchImpl, controller.signal);
  } catch (error) {
    if (signal?.aborted) return outcome('dns-aborted', 'The DNS lookup was cancelled.');
    if (controller.signal.aborted) return outcome('dns-unavailable', 'The DNS lookup took too long. Try again or supply a public key manually.');
    if (error instanceof DnsResponseError) return outcome('dns-invalid-response', error.message);
    return outcome('dns-unavailable', 'The DNS service could not be reached. Check your connection or supply a public key manually.');
  } finally {
    clearTimeout(timeout);
    signal?.removeEventListener('abort', cancel);
  }
}
