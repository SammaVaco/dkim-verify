# Local DKIM verifier

A static, dependency-free browser interface for checking every DKIM signature
in an uploaded `.eml` or pasted raw email. It uses native Web Crypto and a
bundled, cited key catalogue. The first result explains whether the signature
supports the From address; technical details start hidden behind **More
information**. No email is uploaded. By default, missing keys
are looked up through Google Public DNS; cryptographic verification stays in
the browser. Uncheck **Look up missing keys in DNS** for no verification-time
network requests. Citation links are opened only when selected.

## Run and publish

From the repository root:

```sh
python -m http.server 8000 --directory dkim-verifier
```

Open <http://localhost:8000>. Use HTTPS or localhost: browsers require a secure
context for Web Crypto. A recent Chromium, Firefox, or Safari is recommended;
the verifier reports when an algorithm is unavailable in the current browser.
Opening `index.html` as a `file://` URL does not support module/JSON loading.

### Accessing a Docker IP from the host

An address such as `http://172.17.0.5:8000` is not a browser secure context,
even on a private network. The browser withholds `crypto.subtle`; removing
the app's availability check would only move the error to the cryptographic
operation. The JavaScript itself is delivered over the network, even though
verification runs locally. See [MDN's secure-context explanation](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Secure_Contexts).

The shortest workaround is to keep the existing HTTP server and run this
**on the same machine as the browser, outside Docker** (requires `socat`):

```sh
socat TCP-LISTEN:8001,bind=127.0.0.1,reuseaddr,fork TCP:172.17.0.5:8000
```

Open **http://localhost:8001**. The browser sees a loopback address, where Web
Crypto is available over HTTP. Replace the container IP/port if they change.
If the browser is on a different machine from Docker, establish a localhost
tunnel on that browser machine or use trusted HTTPS.

### Optional HTTPS server

`python -m http.server` on Python 3.12 serves plain HTTP. Changing its URL to
`https://` sends a TLS handshake to an HTTP listener, producing binary
`\x16\x03...` / HTTP 400 logs. The unrelated `/favicon.ico` 404 is harmless.

For direct HTTPS, obtain a certificate trusted by the browser and covering the
address you will open, then run this from the repository root:

```sh
python dkim-verifier/scripts/serve_https.py \
  --bind 0.0.0.0 --port 8443 \
  --cert /path/outside-the-site/cert.pem \
  --key /path/outside-the-site/key.pem
```

Open **https://172.17.0.5:8443** when using that container address. The helper
uses Python's standard library and always serves only this site, regardless
of your current directory. It refuses a private key inside the served directory.
It does not create certificates or change certificate trust.

For local certificates, [mkcert](https://github.com/FiloSottile/mkcert) can create
a development CA and a certificate covering `172.17.0.5`, `localhost`, and
`127.0.0.1`. Install/trust that CA **on the browser's machine**, not just inside
the container; copy only the server certificate and server key into the
container. Keep all keys outside the published files. A self-signed certificate
alone still produces a browser certificate warning. Localhost forwarding avoids
this certificate setup. GitHub Pages already serves the site over HTTPS.

Test the optional helper with Python and OpenSSL installed:

```sh
python -m unittest discover -s dkim-verifier/tests -p 'test_https_server.py' -v
```

### GitHub Pages

For GitHub Pages, copy these files into a dedicated site's repository root or
its `docs/` directory, preserving their relative paths:

```text
index.html       style.css       app.js       dkim.js
dns.js           verify-with-dns.js           sender.js
keys.json        sources/        README.md    COVERAGE.md
.nojekyll
```

Select that branch and `/` or `/docs` under **Settings → Pages → Deploy from a
branch**. No build step, npm dependencies, backend, API key, or custom domain
is needed. The `.nojekyll` file keeps the audit documents and data as static
files. Publish only this site's files; the repository root contains unrelated
email investigations. See [GitHub's publishing-source instructions](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site).

## What a report means

The first result focuses on the sender, not algorithms or public keys:

- **Sender domain confirmed:** a valid signature covers the displayed From
  address and comes from exactly that address's domain, using a key supported
  by current or archived DNS evidence. This supports the domain's involvement;
  it does **not** prove that the particular mailbox account or person sent the
  message. DKIM deliberately separates the signer from the claimed author.
  See [RFC 6376's signing identity explanation](https://www.rfc-editor.org/rfc/rfc6376.html#section-1.2).
- **Sender check has limits:** the matching signature covers only part of the
  body, uses a testing key, or has a known revocation in the key collection.
  These cautions stay visible rather than being hidden in technical details.
- **Sender not confirmed:** the summary explains whether signatures fail,
  keys are unavailable or unproven, the signature has expired, or a valid
  signature belongs to another domain. This does not establish that the
  address is forged or that the email was maliciously altered.

The summary shows the actual address, not the potentially misleading display
name. It requires one unambiguous supported mailbox in one From field. Complex
or unsupported address syntax is reported conservatively rather than guessed.
Domain matching is exact and case-insensitive: this tool does not infer a
relationship between sibling domains, a parent domain and a subdomain, or a
third-party provider and the sender. Legitimate signatures in those cases can
still be inspected under **More information**; this is not a DMARC verdict.
One valid applicable signature is enough even if another signature fails.

Click **More information** to inspect every signature and its complete key
evidence. The technical reports distinguish:

- **Valid against a key from current DNS:** the signed bytes match a key just
  retrieved through Google Public DNS, subject to the same signature and time
  checks as archived keys. The report shows the exact key, fingerprint, TXT
  record, lookup citation, retrieval time, and DNS responses. This trusts the
  resolver and does not prove the key was published at a historical date.
- **Valid against an archived DNS key:** the signed bytes match that exact key,
  the key's restrictions allow the signature, and it is not expired at the
  selected time. The report shows the full public key, SHA-256 fingerprint,
  complete DNS TXT record, exact archive lookup, record ID, saved evidence, and
  observation dates. Domain attribution relies on the archive's claims.
- **Matches; domain ownership unconfirmed:** a mathematical match to a supplied
  key or one reconstructed from email signatures. Without a DNS observation,
  this does not authenticate the named domain. Such matches are not displayed
  as authenticated DNS signatures.
- **Does not validate:** the body checksum or header signature differs, or the
  signature is malformed or disallowed. The report identifies the check that
  failed and likely causes. It cannot determine which header changed, whether
  a change was malicious, or whether the correct historical key is missing.
- **Unable to verify:** no suitable key locally or in DNS, a failed DNS lookup,
  no signature, unsupported
  cryptography, invalid clock, or a resource limit. Missing evidence is not
  proof of tampering.
- **Expired:** the cryptographic check matches, but the signature expired by
  the chosen time. An explicit, independently known receipt time can be entered
  for historical analysis. The app never trusts the email's own Date field as
  its receipt time. An absent `x=` means no expiration; `t=` is a signing time.

Upload is preferable to paste, especially for non-UTF-8 messages. Pasted text
is encoded as UTF-8; line endings are normalized to CRLF and reported. Email
bodies and attachments are never rendered as HTML. The app stores no email
in cookies, local storage, or a server. Clearing removes the app's references;
it is not a secure memory-erasure guarantee.

A DKIM match authenticates selected bytes against a domain key. It does not
prove a person's identity, the truth of an email, a trustworthy timestamp, or
protection of every header. It is not SPF, DMARC, ARC, or a mail-delivery verdict.
A signature with `l=` may leave a body suffix unsigned; this is reported even
if all current bytes are covered, because more text could be appended.

## Missing-key DNS lookup and privacy

The browser first tries the local catalogue and any manually supplied key.
Only a signature with no local key is eligible for DNS lookup; a failed match
against an existing key does not trigger it. Browsers cannot send ordinary DNS
packets, so [Google's DNS-over-HTTPS JSON API](https://developers.google.com/speed/public-dns/docs/doh/json)
resolves `selector._domainkey.domain` as a TXT record. DNS aliases (CNAMEs) are
followed, and chunks of the same TXT record are joined before verification.

Google receives the requested DNS names and the browser's IP address, but no
email body, attachments, sender/recipient address fields, cookies, or referrer.
The request disables forwarding the client's subnet to authoritative servers
with `edns_client_subnet=0.0.0.0/0`. The app trusts Google's HTTPS response; it
does not independently validate DNSSEC. A malicious email can choose a signing
domain whose DNS operator observes the resolver's query. Disable the checkbox
before checking mail if even this name disclosure is unacceptable.

Requests are limited to ten distinct missing keys per check, with bounded
alias traversal and an eight-second timeout per key. Repeated signatures using
the same key share a lookup. Editing or clearing input cancels in-flight
lookups. Live keys and response evidence are held only for that check, not
written to the bundled catalogue or browser storage. Missing/removed keys,
resolver failures, and ambiguous DNS answers produce explanations rather than
claims that the email was altered. A current key may differ from a historical
key: DNS fallback cannot supply a complete historical archive.

## Historical key coverage and evidence

The initial snapshot contains **202 records across 39 exact domains and 16
provider groups: 183 nonempty key records and 19 revocations**. It covers
Google/Gmail, Microsoft/Outlook, Yahoo/AOL, Apple, Proton, Fastmail, Zoho,
GMX/Web.de, Yandex, Mail.ru, QQ, NetEase, SES, SendGrid, Mailgun, and Mandrill.
One nonempty historical QQ key is only 768 bits and is rejected as too weak.

**This is not a complete five-year archive of every major provider's keys.**
Available records include older keys, but many DNS observation histories start
in 2024. Custom domains, regional aliases, missing selectors, and unarchived
rotations need additional evidence. [COVERAGE.md](COVERAGE.md) gives measured
coverage per domain. A selector containing a year is not proof of its age.

The source is the [ZK Email DKIM Archive](https://archive.zk.email/about).
Its [pinned provenance documentation](https://github.com/zkemail/archive/blob/aeff0fa5002d0e3b5f51d3edb54ec8c15cc575a0/docs/signed-observations.md)
distinguishes `live_dns` observations from `gcd_recovered` keys. Recovered keys
come from submitted messages whose authenticity the archive does not establish.
First/last observations do not prove continuous publication or key ownership
at an email's claimed date. Historical matches can remain possible after a
key was removed or revoked; they do not override revocation or establish when
the signature was made. The collection retains revocation records as evidence.

Every catalogue entry names a local, untouched API response and its SHA-256
digest, along with the original URL and record ID. The digest detects changes
relative to the bundled catalogue; it is not an independent timestamp or proof
of origin. This version does not validate DNSSEC or the archive's signed JWS
attestations. These are explicit trust limits, not hidden validation steps.

Refresh from `dkim-verifier/` with Node 20+:

```sh
node scripts/update-keys.mjs 2>&1 | tee /tmp/dkim-keys-refresh.log
npm test
```

The script queries only the documented public domains, respects rate limits,
retains previous keys, and saves new dated source snapshots. Review changes
before publishing. You can also supply a public key and citation in the page;
those inputs are local and are not added to the trusted archive catalogue.

## Audit and test

Runtime source is [dkim.js](dkim.js), [dns.js](dns.js),
[verify-with-dns.js](verify-with-dns.js), [sender.js](sender.js), [app.js](app.js), [index.html](index.html),
and [style.css](style.css). There is no minification, bundled library, CDN,
service worker, or custom cryptographic arithmetic. The DKIM core remains
network-free; the DNS module is the only source of external requests.
Web Crypto verifies RSA signatures and Ed25519 signatures; the readable core
implements DKIM parsing, byte normalization, header selection, and key policy.

From `dkim-verifier/`, use Node 20+:

```sh
npm test
```

The suite includes independently generated and dkimpy-verified RSA/Ed25519
fixtures, all four canonicalization combinations, binary bytes, repeated and
oversigned headers, multiple signatures, partial bodies, tampering, expiry,
key restrictions, snapshot/citation integrity, and mocked DNS fallback and
request-privacy checks. Sender-summary tests cover address ambiguity, exact
domain matching, key provenance, multiple signatures and visible caveats.
Fixture generation is
documented in [tests/fixtures/README.md](tests/fixtures/README.md). Runtime and
Node tests require no npm install; Python packages are only for regenerating
the independent fixtures.

The browser acceptance check uses Playwright. With the local server
running on port 8000, run these from `dkim-verifier/`:

```sh
npm install --no-save --package-lock=false playwright
npx playwright install chromium
npm run test:browser
```

The browser check uses synthetic fixtures and explicitly mocked archive evidence
for the authenticated-result display. It checks real upload/paste controls,
binary bytes, RSA/Ed25519, changed headers/body, missing keys, citation display,
expiration, safe text rendering, and zero network requests with DNS disabled or
a matching registry entry. Mocked DNS tests cover missing-key success, aliases,
TXT chunks, lookup failure, exact evidence display, and request privacy.
The sender verdict appears before initially collapsed technical details, and
the browser tests check that expanding them preserves the full audit report.
It restores the actual catalogue after the check. Playwright and its operating
system browser libraries are test tools only, not website dependencies.
Set `DKIM_TEST_URL` to use a different local server URL. Screenshots are saved
under the ignored `output/playwright/` directory.

Limits are 20 MiB per message, 1 MiB of headers, 100 signatures, and 4096 decoded
public-key bytes. RSA keys under 1024 bits and obsolete SHA-1 signatures are
rejected. Future signing timestamps are reported without an implicit clock
grace period. Signing domains/selectors must be ASCII (punycode is supported),
and signing identities must decode to ASCII. Internationalized DKIM identifiers
requiring [RFC 8616](https://www.rfc-editor.org/rfc/rfc8616.html) UTF-8/IDNA
processing are reported as unsupported, not invalid. Unicode message headers
and body bytes are supported. Supported standards are [RFC 6376](https://www.rfc-editor.org/rfc/rfc6376.html),
[RFC 8301](https://www.rfc-editor.org/rfc/rfc8301.html), and
[RFC 8463](https://www.rfc-editor.org/rfc/rfc8463.html).
