const MAX_MESSAGE_BYTES = 20 * 1024 * 1024;
const MAX_HEADER_BYTES = 1024 * 1024;
const splitList = value => value.split(':').map(trimWhitespace);
const digest = async value => new Uint8Array(await crypto.subtle.digest('SHA-256', value));

function trimWhitespace(value) {
  let start = 0;
  let end = value.length;
  while (start < end && (value[start] === ' ' || value[start] === '\t')) start++;
  while (end > start && (value[end - 1] === ' ' || value[end - 1] === '\t')) end--;
  return value.slice(start, end);
}

function toBytes(value) {
  const bytes = new Uint8Array(value.length);
  for (let offset = 0; offset < value.length; offset++) bytes[offset] = value.charCodeAt(offset);
  return bytes;
}

class VerificationError extends Error {
  constructor(code, explanation, status = 'invalid') {
    super(explanation);
    Object.assign(this, { code, explanation, status });
  }
}

function reject(code, explanation, status) {
  throw new VerificationError(code, explanation, status);
}

function failure(error, report = { warnings: [] }) {
  return Object.assign(report, error instanceof VerificationError
    ? { status: error.status, code: error.code, explanation: error.explanation }
    : { status: 'unverifiable', code: 'verification-error', explanation: 'The browser could not complete this check. Try a current browser, and check the key and email format.' });
}

function binaryString(bytes) {
  const chunks = [];
  for (let offset = 0; offset < bytes.length; offset += 32768) {
    chunks.push(String.fromCharCode(...bytes.subarray(offset, offset + 32768)));
  }
  return chunks.join('');
}

function parseMessage(bytes) {
  if (!(bytes instanceof Uint8Array)) reject('malformed-message', 'Provide the original email as bytes from an .eml file.');
  if (bytes.length > MAX_MESSAGE_BYTES) reject('size-limit', 'This local verifier accepts emails up to 20 MiB.', 'unverifiable');
  const original = binaryString(bytes);
  const normalized = original.replace(/\r?\n/g, '\r\n');
  const boundary = normalized.indexOf('\r\n\r\n');
  if (boundary < 0) reject('malformed-message', 'The email is missing the blank line between its headers and body. Upload the original .eml file.');
  if (boundary > MAX_HEADER_BYTES) reject('size-limit', 'The email headers exceed this verifier’s 1 MiB limit.', 'unverifiable');
  const headers = [];
  for (const line of normalized.slice(0, boundary).split('\r\n')) {
    if (/[\x00-\x08\x0b-\x1f\x7f]/.test(line)) reject('malformed-message', 'An email header contains an invalid control character.');
    if (/^[ \t]/.test(line)) {
      if (!headers.length) reject('malformed-message', 'The first header line is an unexpected continuation.');
      headers.at(-1).raw += `\r\n${line}`;
      continue;
    }
    const field = /^([!-9;-~]+)[ \t]*:/.exec(line);
    if (!field) reject('malformed-message', 'An email header is malformed. Paste the complete raw email or upload its .eml file.');
    headers.push({ name: field[1].toLowerCase(), raw: line });
  }
  return { headers, body: normalized.slice(boundary + 4), bodyCache: new Map(), bodyHashes: new Map(),
    warnings: original === normalized ? [] : ['LF line endings were converted to standard email CRLF line endings.'] };
}

function parseTags(value, kind) {
  const malformed = () => reject(`malformed-${kind}`, `The ${kind} contains malformed or repeated name=value fields.`, kind === 'key' ? 'unverifiable' : 'invalid');
  if (/\r\n(?![ \t])|\r(?!\n)|(?<!\r)\n|[^\x09\x0d\x0a\x20-\x7e]/.test(value)) malformed();
  const parts = value.replace(/\r\n/g, '').split(';');
  if (trimWhitespace(parts.at(-1)) === '') parts.pop();
  const tags = Object.create(null);
  for (const part of parts) {
    const match = /^[ \t]*([A-Za-z][A-Za-z0-9_]*)[ \t]*=([\x09\x20-\x7e]*)$/.exec(part);
    if (!match || Object.hasOwn(tags, match[1])) malformed();
    tags[match[1]] = trimWhitespace(match[2]);
  }
  return tags;
}

function decodeBase64(value, kind) {
  const compact = value.replace(/[ \t\r\n]/g, '');
  if (!compact || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(compact)) {
    reject(`malformed-${kind}`, `The ${kind} contains damaged base64 data. Copying or truncating an email or key can cause this.`, kind === 'key' ? 'unverifiable' : 'invalid');
  }
  const decoded = atob(compact);
  if (btoa(decoded) !== compact) reject(`malformed-${kind}`, `The ${kind} has a noncanonical base64 encoding.`, kind === 'key' ? 'unverifiable' : 'invalid');
  return toBytes(decoded);
}

function validDomain(domain, selector = false) {
  return domain.length <= 253 && (selector || domain.includes('.')) && domain.split('.').every(label =>
    (selector ? /^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$/ : /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/).test(label));
}

function requireAsciiIdentifier(value) {
  if (/[\x80-\xff]/.test(value)) reject('unsupported-internationalized', 'This signature uses internationalized DKIM identifiers, which this verifier does not yet support. This does not mean the signature is invalid.', 'unverifiable');
}

function signatureDetails(header, report) {
  const value = header.raw.slice(header.raw.indexOf(':') + 1);
  for (const part of value.split(';')) {
    if (/^[ \t\r\n]*[dsi][ \t\r\n]*=/.test(part)) requireAsciiIdentifier(part);
  }
  const tags = parseTags(value, 'signature');
  report.domain = tags.d?.toLowerCase();
  report.selector = tags.s?.toLowerCase();
  report.algorithm = tags.a;
  for (const required of ['v', 'a', 'b', 'bh', 'd', 'h', 's']) {
    if (!tags[required]) reject('malformed-signature', `The signature is missing its required ${required}= field.`);
  }
  if (tags.v !== '1') reject('unsupported-version', 'This signature uses an unsupported DKIM version.', 'unverifiable');
  if (!['rsa-sha256', 'ed25519-sha256'].includes(tags.a)) {
    reject('unsupported-algorithm', 'This verifier supports RSA-SHA256 and Ed25519-SHA256. Obsolete SHA-1 signatures are not accepted.', 'unverifiable');
  }
  if (!validDomain(tags.d) || !validDomain(tags.s, true) || `${tags.s}._domainkey.${tags.d}`.length > 253) {
    reject('malformed-signature', 'The signature has an invalid signing domain or key selector.');
  }
  const modes = (tags.c ?? 'simple/simple').split('/');
  if (modes.length > 2 || !modes.every(mode => ['simple', 'relaxed'].includes(mode))) {
    reject('unsupported-canonicalization', 'This signature uses unsupported rules for normalizing email formatting.', 'unverifiable');
  }
  const [headerMode, bodyMode = 'simple'] = modes;
  report.canonicalization = `${headerMode}/${bodyMode}`;
  report.signedHeaders = splitList(tags.h).map(name => name.toLowerCase());
  if (!report.signedHeaders.every(name => /^[!-9;-~]+$/.test(name))) reject('malformed-signature', 'The list of signed email headers is malformed.');
  if (!report.signedHeaders.includes('from')) reject('unsigned-from', 'The signature does not protect the From header, which DKIM requires.');
  const queryMethods = splitList(tags.q ?? 'dns/txt');
  if (!queryMethods.every(method => /^[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\/[\s\S]*)?$/.test(method) &&
    !/=(?![0-9A-F]{2})|\|/.test(method))) reject('malformed-signature', 'The signature’s key lookup method list is malformed.');
  if (!queryMethods.includes('dns/txt')) {
    reject('unsupported-query', 'This signature requires a key lookup method that the bundled DNS key collection does not support.', 'unverifiable');
  }
  const identity = (tags.i ?? `@${tags.d}`).replace(/[ \t]/g, '');
  if (/=(?![0-9A-F]{2})/.test(identity)) reject('malformed-signature', 'The signing identity has damaged quoted-printable encoding.');
  const decodedIdentity = identity.replace(/=([0-9A-F]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
  requireAsciiIdentifier(decodedIdentity);
  const separator = decodedIdentity.lastIndexOf('@');
  const localPart = decodedIdentity.slice(0, separator);
  const atom = /^[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+$/;
  const quoted = /^"(?:[\x20-\x21\x23-\x5b\x5d-\x7e]|\\[\x20-\x7e])*"$/;
  if (localPart && !quoted.test(localPart) && !localPart.split('.').every(part => atom.test(part))) {
    reject('malformed-signature', 'The signature’s signing identity has a malformed address.');
  }
  const identityDomain = decodedIdentity.slice(separator + 1).toLowerCase();
  if (!decodedIdentity.includes('@') || !validDomain(identityDomain) ||
    !(identityDomain === report.domain || identityDomain.endsWith(`.${report.domain}`))) {
    reject('identity-domain', 'The identity named in this signature does not belong to its signing domain.');
  }
  for (const [tag, field] of [['t', 'signingTime'], ['x', 'expiresAt']]) {
    if (tags[tag] !== undefined) {
      if (!/^\d{1,12}$/.test(tags[tag])) reject('malformed-signature', 'The signature has a malformed timestamp.');
      report[field] = Number(tags[tag]);
    }
  }
  if (report.expiresAt !== undefined && report.signingTime !== undefined && report.expiresAt <= report.signingTime) {
    reject('malformed-signature', 'The signature expires at or before its claimed signing time.');
  }
  const bodyHash = decodeBase64(tags.bh, 'signature');
  const signature = decodeBase64(tags.b, 'signature');
  if (bodyHash.length !== 32 || (tags.a === 'ed25519-sha256' && signature.length !== 64)) {
    reject('malformed-signature', 'The signature or body checksum has the wrong length.');
  }
  return { tags, headerMode, bodyMode, identityDomain, bodyHash, signature };
}

function canonicalHeader(raw, mode) {
  if (mode === 'simple') return raw;
  const colon = raw.indexOf(':');
  const name = trimWhitespace(raw.slice(0, colon)).toLowerCase();
  const value = trimWhitespace(raw.slice(colon + 1).replace(/\r\n/g, '').replace(/[ \t]+/g, ' '));
  return `${name}:${value}`;
}

function canonicalBody(body, mode) {
  if (mode === 'relaxed') body = body.replace(/[ \t]+/g, ' ').replace(/ +(?=\r\n|$)/g, '');
  let end = body.length;
  while (end >= 2 && body.slice(end - 2, end) === '\r\n') end -= 2;
  body = body.slice(0, end);
  return body || mode === 'simple' ? `${body}\r\n` : '';
}

function signingBytes(message, signatureHeader, report, headerMode) {
  const available = new Map();
  for (const header of message.headers) {
    if (header === signatureHeader) continue;
    if (!available.has(header.name)) available.set(header.name, []);
    available.get(header.name).push(header);
  }
  const selected = [];
  for (const name of report.signedHeaders) {
    const header = available.get(name)?.pop();
    if (header) selected.push(`${canonicalHeader(header.raw, headerMode)}\r\n`);
  }
  const colon = signatureHeader.raw.indexOf(':');
  const withoutSignature = signatureHeader.raw.slice(0, colon + 1) + signatureHeader.raw.slice(colon + 1)
    .replace(/(^|;)([ \t\r\n]*b[ \t\r\n]*=)[^;]*/, '$1$2');
  selected.push(canonicalHeader(withoutSignature, headerMode));
  return toBytes(selected.join(''));
}

function derWrap(tag, contents) {
  const length = contents.length;
  const encodedLength = length < 128 ? [length] : length < 256 ? [0x81, length] : [0x82, length >> 8, length & 255];
  return Uint8Array.of(tag, ...encodedLength, ...contents);
}

async function importKey(record, details) {
  if (typeof record !== 'string' || record.length > 16384) reject('malformed-key', 'The public-key record is missing or exceeds the size limit.', 'unverifiable');
  const tags = parseTags(record, 'key');
  if (tags.v !== undefined && (tags.v !== 'DKIM1' || Object.keys(tags)[0] !== 'v')) reject('malformed-key', 'The public key has an unsupported version or misplaced version field.', 'unverifiable');
  if (!Object.hasOwn(tags, 'p')) reject('malformed-key', 'The public-key record contains no public key.', 'unverifiable');
  if (!tags.p) reject('revoked-key', 'This record revokes the key: it contains no public key with which to check the signature.', 'unverifiable');
  if ((tags.k ?? 'rsa') !== details.tags.a.split('-')[0]) reject('key-type', 'The available public key is for a different signing algorithm.', 'unverifiable');
  for (const name of ['h', 's', 't']) {
    if (tags[name] !== undefined && !splitList(tags[name]).every(value =>
      (name === 's' && value === '*') || /^[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/.test(value))) {
      reject('malformed-key', 'The public-key record has a malformed hash, service, or flag list.', 'unverifiable');
    }
  }
  const flags = splitList(tags.t ?? '');
  if ((tags.h !== undefined && !splitList(tags.h).includes('sha256')) ||
    (tags.s !== undefined && !splitList(tags.s).some(service => ['*', 'email'].includes(service))) ||
    (flags.includes('s') && details.identityDomain !== details.tags.d.toLowerCase())) {
    reject('key-restriction', 'The public-key record does not permit this signature’s hash, email service, or signing identity.');
  }
  const publicBytes = decodeBase64(tags.p, 'key');
  if (publicBytes.length > 4096) reject('key-size', 'The public key exceeds this verifier’s size limit.', 'unverifiable');
  let key;
  try {
    if (details.tags.a === 'ed25519-sha256') {
      if (publicBytes.length !== 32) reject('malformed-key', 'An Ed25519 public key must contain exactly 32 bytes.', 'unverifiable');
      key = await crypto.subtle.importKey('raw', publicBytes, 'Ed25519', false, ['verify']);
    } else {
      const algorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
      try {
        key = await crypto.subtle.importKey('spki', publicBytes, algorithm, false, ['verify']);
      } catch {
        const rsaIdentifier = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];
        const bitString = derWrap(0x03, Uint8Array.of(0, ...publicBytes));
        const spki = derWrap(0x30, Uint8Array.of(...rsaIdentifier, ...bitString));
        key = await crypto.subtle.importKey('spki', spki, algorithm, false, ['verify']);
      }
      if (key.algorithm.modulusLength < 1024) reject('weak-key', 'This RSA key is shorter than 1024 bits and is too weak to accept.');
    }
  } catch (error) {
    if (error instanceof VerificationError) throw error;
    if (error.name === 'NotSupportedError') reject('unsupported-crypto', 'This browser does not support the signature’s cryptography. Try a current browser.', 'unverifiable');
    reject('malformed-key', 'The public-key bytes cannot be read as the required cryptographic key.', 'unverifiable');
  }
  return { key, publicBytes, testing: flags.includes('y') };
}

async function verifySignature(message, header, keys, now) {
  const report = { warnings: [...message.warnings] };
  try {
    const details = signatureDetails(header, report);
    if (message.headers.filter(field => field.name === 'from').length !== 1) {
      reject('ambiguous-from', 'The email must contain exactly one From header. Missing or repeated From headers make the sender display ambiguous.');
    }
    if (!globalThis.crypto?.subtle) reject('unsupported-crypto', 'Web Crypto is unavailable. Open this page over HTTPS or localhost in a current browser.', 'unverifiable');
    if (!message.bodyCache.has(details.bodyMode)) message.bodyCache.set(details.bodyMode, canonicalBody(message.body, details.bodyMode));
    let body = message.bodyCache.get(details.bodyMode);
    if (details.tags.l !== undefined) {
      report.bodyLengthLimited = true;
      if (!/^\d{1,76}$/.test(details.tags.l) || BigInt(details.tags.l) > BigInt(body.length)) {
        reject('body-length', 'The signature’s body length is invalid or longer than the available email body. The file may be truncated.');
      }
      const signedLength = Number(details.tags.l);
      report.warnings.push(`This signature protects only the first ${signedLength} normalized body bytes. ${body.length - signedLength} current bytes are unsigned; additional text can be appended without breaking this signature.`);
      body = body.slice(0, signedLength);
    }
    const hashKey = `${details.bodyMode}:${body.length}`;
    if (!message.bodyHashes.has(hashKey)) message.bodyHashes.set(hashKey, await digest(toBytes(body)));
    const actualHash = message.bodyHashes.get(hashKey);
    report.bodyHashMatches = actualHash.every((byte, index) => byte === details.bodyHash[index]);
    if (!report.bodyHashMatches) reject('body-mismatch', 'The email body does not match the checksum in this signature. Text, attachments, or formatting may have changed during editing, forwarding, export, or copying. Upload the original .eml file if possible.');
    const candidates = keys.filter(key => key.domain?.toLowerCase() === report.domain && key.selector?.toLowerCase() === report.selector);
    if (!candidates.length) reject('missing-key', `No local public key is available for ${report.selector}._domainkey.${report.domain}. This does not show that the email was altered; the collection may lack the required historical key.`, 'unverifiable');
    const hasRevocation = candidates.some(candidate => {
      try { return parseTags(candidate.record, 'key').p === ''; } catch { return false; }
    });
    report.hasRevocation = hasRevocation;
    if (hasRevocation) report.warnings.push('The collection also contains a revocation for this domain and selector. A match to an older key does not establish whether it was authorized at the selected time.');
    const input = signingBytes(message, header, report, details.headerMode);
    const cryptoInput = report.algorithm === 'ed25519-sha256' ? await digest(input) : input;
    let keyFailure;
    let attempted = false;
    for (const candidate of candidates) {
      try {
        const imported = await importKey(candidate.record, details);
        const matches = await crypto.subtle.verify(imported.key.algorithm.name, imported.key, details.signature, cryptoInput);
        attempted = true;
        if (!matches) continue;
        report.signatureMatches = true;
        report.testingKey = imported.testing;
        report.key = candidate;
        report.keyFingerprint = Array.from(await digest(imported.publicBytes), byte => byte.toString(16).padStart(2, '0')).join('');
        if (imported.testing) report.warnings.push('The key owner marked this as a testing key; do not treat it as a production endorsement.');
        if (report.signingTime !== undefined && report.signingTime > now) reject('future-timestamp', 'The signature claims it was made after the selected verification time. Check the clock or choose an appropriate historical date.', 'unverifiable');
        if (report.expiresAt !== undefined && now > report.expiresAt) reject('expired-signature', 'The signed content matches this key, but the signature had expired by the selected verification time. A historical date can check its status at that time.', 'expired');
        return Object.assign(report, { status: 'valid', code: 'verified', explanation: 'The signed headers and covered body match this public key. This establishes a cryptographic match; consult the key’s cited evidence to assess its connection to the signing domain.' });
      } catch (error) {
        if (report.signatureMatches) throw error;
        keyFailure = error;
      }
    }
    if (!attempted && keyFailure) throw keyFailure;
    report.signatureMatches = false;
    reject('signature-mismatch', 'The signed headers or signature do not match any available key. A header or the signature may have changed, or the correct historical key may be missing. This check cannot identify which header changed.');
  } catch (error) {
    return failure(error, report);
  }
}

export async function verifyEmail(bytes, keys, options = {}) {
  let fromHeaders = [];
  try {
    const now = options.now ?? Math.floor(Date.now() / 1000);
    if (!Number.isSafeInteger(now) || now < 0) reject('invalid-time', 'Choose a valid verification time on or after January 1, 1970.', 'unverifiable');
    const message = parseMessage(bytes);
    fromHeaders = message.headers.filter(header => header.name === 'from')
      .map(header => trimWhitespace(header.raw.slice(header.raw.indexOf(':') + 1).replace(/\r\n/g, '')));
    const signatures = message.headers.filter(header => header.name === 'dkim-signature');
    if (!signatures.length) reject('no-signature', 'This email contains no DKIM-Signature header. Its authenticity cannot be checked with DKIM.', 'unverifiable');
    if (signatures.length > 100) reject('signature-limit', 'This email exceeds the limit of 100 signatures per check.', 'unverifiable');
    const results = [];
    for (const header of signatures) results.push(await verifySignature(message, header, keys, now));
    return { fromHeaders, signatures: results };
  } catch (error) {
    return { fromHeaders, signatures: [failure(error)] };
  }
}
