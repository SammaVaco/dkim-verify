const ATOM = String.raw`[A-Za-z0-9!#$%&'*+\-/=?^_\x60{|}~]+`;
const QUOTED = String.raw`"(?:[\x09\x20-\x21\x23-\x5b\x5d-\x7e]|\\[\x09\x20-\x7e])*"`;
const ADDRESS = new RegExp(`^(${ATOM}(?:\\.${ATOM})*|${QUOTED})[ \\t]*@[ \\t]*([A-Za-z0-9.-]+)$`);
const DISPLAY_WORD = String.raw`(?:[A-Za-z0-9!#$%&'*+\-/=?^_\x60{|}~.\x80-\uffff]+|${QUOTED})`;
const DISPLAY_NAME = new RegExp(`^${DISPLAY_WORD}(?:[ \\t]+${DISPLAY_WORD})*$`);
const trimWhitespace = value => value.replace(/^[ \t]+|[ \t]+$/g, '');

export function keyProvenance(key) {
  if (key?.sources?.some(source => source.type === 'dns')) {
    return { kind: 'dns', origin: 'live', label: 'Current DNS key', explanation: 'This key was retrieved from current DNS through Google Public DNS. This check trusts that resolver; it does not prove the key was published at a historical date or establish when the email was sent.' };
  }
  const observations = (key?.sources ?? []).flatMap(source => source.observations ?? []);
  if (observations.some(observation => observation.source === 'live_dns')) {
    return { kind: 'dns', label: 'Archived DNS key', explanation: 'The archive reports observing this key in the signing domain’s DNS. This offline check trusts that archive evidence; it does not establish when this email was sent.' };
  }
  return { kind: 'unconfirmed', label: 'Domain ownership unconfirmed', explanation: 'The signed content matches this key, but there is no bundled DNS observation tying this key to the domain. A reconstructed or supplied key alone does not authenticate the sender.' };
}

function withoutComments(value) {
  let cleaned = '';
  let depth = 0;
  let quoted = false;
  let escaped = false;
  for (const character of value) {
    if (escaped) {
      if (!depth) cleaned += character;
      escaped = false;
    } else if (character === '\\' && (quoted || depth)) {
      if (!depth) cleaned += character;
      escaped = true;
    } else if (depth) {
      if (character === '(') depth++;
      if (character === ')') depth--;
    } else if (character === '"') {
      quoted = !quoted;
      cleaned += character;
    } else if (!quoted && character === '(') {
      cleaned += ' ';
      depth++;
    } else if (!quoted && character === ')') {
      return null;
    } else {
      cleaned += character;
    }
  }
  return depth || quoted || escaped ? null : trimWhitespace(cleaned);
}

function parseMailbox(fromHeaders) {
  if (!Array.isArray(fromHeaders) || !fromHeaders.length) return { code: 'missing-from' };
  if (fromHeaders.length !== 1) return { code: 'ambiguous-from' };
  const unsupported = { code: 'unsupported-from' };
  const value = fromHeaders[0];
  if (typeof value !== 'string' || value.length > 8192 || /[\x00-\x08\x0b-\x1f\x7f]/.test(value)) return unsupported;
  const cleaned = withoutComments(value);
  if (!cleaned) return unsupported;
  let quoted = false;
  let escaped = false;
  let opening = -1;
  let closing = -1;
  for (let offset = 0; offset < cleaned.length; offset++) {
    const character = cleaned[offset];
    if (escaped) escaped = false;
    else if (quoted && character === '\\') escaped = true;
    else if (character === '"') quoted = !quoted;
    else if (!quoted) {
      if (',:;'.includes(character)) return unsupported;
      if (character === '<') {
        if (opening !== -1 || closing !== -1) return unsupported;
        opening = offset;
      }
      if (character === '>') {
        if (opening === -1 || closing !== -1) return unsupported;
        closing = offset;
      }
    }
  }
  let address = cleaned;
  if (opening !== -1) {
    if (closing === -1 || trimWhitespace(cleaned.slice(closing + 1))) return unsupported;
    const display = trimWhitespace(cleaned.slice(0, opening));
    if (display && !DISPLAY_NAME.test(display)) return unsupported;
    address = trimWhitespace(cleaned.slice(opening + 1, closing));
  }
  const match = ADDRESS.exec(address);
  if (!match) return unsupported;
  const [, localPart, originalDomain] = match;
  const domain = originalDomain.toLowerCase();
  if (localPart.length > 64 || domain.length > 253 || !domain.includes('.') ||
    !domain.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) return unsupported;
  address = `${localPart}@${domain}`;
  return address.length > 254 ? unsupported : { address, domain };
}

function limitations(signature) {
  const notes = [];
  if (signature.bodyLengthLimited) notes.push('Only part of the message is protected, or additional text can be added without invalidating this signature. Do not assume all of the email came from the sender.');
  if (signature.testingKey) notes.push('The domain marked this key for testing, not as a production endorsement of the email.');
  if (signature.hasRevocation) notes.push('A record says this key name was withdrawn. A match with an older key does not establish whether it was authorized at the selected time.');
  return notes;
}

function verdict(status, code, mailbox, explanation, notes = []) {
  const titles = { confirmed: 'Sender domain confirmed', limited: 'Sender check has limits', unconfirmed: 'Sender not confirmed', failed: 'Sender not confirmed' };
  return { status, code, title: titles[status], address: mailbox.address ?? null, explanation, notes };
}

export function senderSummary(report) {
  const mailbox = parseMailbox(report.fromHeaders);
  if (mailbox.code) {
    const explanations = {
      'missing-from': 'There is no readable From address to check. This does not establish who sent the email.',
      'ambiguous-from': 'The email has more than one From field, so it does not identify one unambiguous sender address.',
      'unsupported-from': 'The From field is ambiguous or uses an address format this verifier cannot safely interpret. The sender address cannot be confirmed.',
    };
    return verdict('unconfirmed', mailbox.code, mailbox, explanations[mailbox.code]);
  }
  const signatures = report.signatures ?? [];
  const related = signatures.filter(signature => signature.domain?.toLowerCase() === mailbox.domain);
  const matching = related.filter(signature => signature.status === 'valid');
  const protectedFrom = matching.filter(signature => signature.signedHeaders?.some(name => name.toLowerCase() === 'from'));
  const authorized = protectedFrom.filter(signature => keyProvenance(signature.key).kind === 'dns');
  const best = authorized.find(signature => !limitations(signature).length) ?? authorized[0];
  if (best) {
    const notes = limitations(best);
    const limited = notes.length > 0;
    notes.push(keyProvenance(best.key).origin === 'live'
      ? 'This uses a key from current DNS; it does not establish when the email was sent or whether the key was published at that time.'
      : 'This relies on the archive’s record of a DNS key; it does not establish when the email was sent or whether the key was published at that time.');
    const explanation = limited
      ? `A signature for ${mailbox.domain} matches the email with ${mailbox.address} in its From field, but the limitations below prevent a full sender confirmation.`
      : `${mailbox.domain} attests that this email with came from ${mailbox.address}.`;
    return verdict(limited ? 'limited' : 'confirmed', limited ? 'sender-domain-limited' : 'sender-domain-confirmed', mailbox, explanation, notes);
  }
  if (protectedFrom.length) {
    return verdict('unconfirmed', 'unconfirmed-key', mailbox,
      `The signature matches the protected content and ${mailbox.address} in the From field, but there is no DNS evidence tying its key to ${mailbox.domain}. A supplied or reconstructed key alone cannot confirm that this domain authorized the email.`, limitations(protectedFrom[0]));
  }
  if (matching.length) return verdict('unconfirmed', 'unsigned-from', mailbox, `The signature does not protect the From field, so it cannot confirm ${mailbox.address}.`);

  const relevant = related.find(signature => signature.status === 'expired')
    ?? related.find(signature => signature.code === 'future-timestamp')
    ?? related.find(signature => signature.status === 'unverifiable')
    ?? related.find(signature => signature.status === 'invalid');
  if (!relevant && signatures.some(signature => signature.status === 'valid')) {
    return verdict('unconfirmed', 'different-signing-domain', mailbox,
      `The matching signature names a different domain, not ${mailbox.domain}, so it does not confirm ${mailbox.address}. Another sending service can legitimately sign an email, but this check requires an exact sender-domain match.`);
  }
  const reason = relevant ?? signatures[0];
  const code = reason?.code ?? 'no-signature';
  const uncertainty = 'This is not proof that the sender address was forged.';
  if (code === 'no-signature') return verdict('unconfirmed', code, mailbox, `This email has no DKIM signature to confirm ${mailbox.address}. ${uncertainty}`);
  if (code === 'expired-signature') return verdict('unconfirmed', code, mailbox, `The protected content matches a key, but the signature expired before the selected check time. It cannot currently confirm ${mailbox.address}. ${uncertainty}`);
  if (code === 'future-timestamp') return verdict('unconfirmed', code, mailbox, `The signature claims a date after the selected check time. Check the date before drawing a conclusion about ${mailbox.address}. ${uncertainty}`);
  if (code === 'revoked-key') return verdict('unconfirmed', code, mailbox, `The domain has withdrawn the key needed to check this signature, so ${mailbox.address} cannot be confirmed. ${uncertainty}`);
  if (code === 'missing-key' || code.startsWith('dns-')) return verdict('unconfirmed', code, mailbox, `The public information needed to check the signature for ${mailbox.address} is unavailable. Missing or retired keys can cause this. ${uncertainty}`);
  if (reason?.status === 'invalid') {
    return verdict('failed', 'signature-failed', mailbox,
      `The signature does not validate for ${mailbox.address}. The email or signature may have changed, or the matching historical key may be unavailable. This does not prove the sender address is forged.`);
  }
  return verdict('unconfirmed', code, mailbox, `This verifier could not complete the sender check for ${mailbox.address}. Missing evidence or an unsupported format may prevent verification. ${uncertainty}`);
}
