import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { verifyEmail } from "../dkim.js";

const fixtures = JSON.parse(readFileSync(new URL("./fixtures/vectors.json", import.meta.url)));
const fixtureBytes = (name) => Buffer.from(fixtures.messages[name], "base64");
const verify = (bytes, keys = fixtures.keys, now = fixtures.verificationTime) =>
  verifyEmail(bytes, keys, { now });

function replace(bytes, original, replacement) {
  const text = bytes.toString("latin1");
  assert.ok(text.includes(original), `Fixture must contain ${JSON.stringify(original)}`);
  return Buffer.from(text.replace(original, replacement), "latin1");
}

function assertStatuses(report, expected) {
  assert.deepEqual(report.signatures.map((signature) => signature.status), expected,
    JSON.stringify(report.signatures, null, 2));
}

for (const name of Object.keys(fixtures.messages)) {
  test(`independent dkimpy vector: ${name}`, async () => {
    const report = await verify(fixtureBytes(name));
    const count = name === "multiple" || name === "signed-signature" ? 2 : 1;
    assertStatuses(report, Array(count).fill("valid"));
    for (const signature of report.signatures) {
      assert.equal(signature.bodyHashMatches, true);
      assert.equal(signature.signatureMatches, true);
      assert.ok(signature.key.record.includes("p="));
      assert.ok(signature.keyFingerprint);
    }
  });
}

test("raw non-UTF-8 body bytes must survive verification", async () => {
  const original = fixtureBytes("rsa-relaxed-relaxed");
  assert.ok(original.includes(Buffer.from([0xff, 0x80])));
  const corrupted = Buffer.from(original.toString("utf8"), "utf8");
  const report = await verify(corrupted);
  assertStatuses(report, ["invalid"]);
  assert.equal(report.signatures[0].bodyHashMatches, false);
});

test("RSA key material accepts independently verified PKCS#1 encoding", async () => {
  const keys = [{ ...fixtures.keys[0], record: fixtures.rsaPkcs1Record }];
  assertStatuses(await verify(fixtureBytes("rsa-relaxed-relaxed"), keys), ["valid"]);
});

test("relaxed modes tolerate allowed header folding and body whitespace", async () => {
  let message = fixtureBytes("rsa-relaxed-relaxed");
  message = replace(message, "Subject: DKIM\t fixture\r\n\twith a folded subject",
    "sUbJeCt:\t DKIM fixture with a folded subject  ");
  message = replace(message, "next\t\tcolumn \r\n", "next column\t\t\r\n");
  assertStatuses(await verify(message), ["valid"]);
});

test("simple header mode detects a whitespace change", async () => {
  const message = replace(fixtureBytes("rsa-simple-relaxed"),
    "Subject: DKIM\t fixture", "Subject: DKIM fixture");
  assertStatuses(await verify(message), ["invalid"]);
});

test("simple body mode detects a whitespace change", async () => {
  const message = replace(fixtureBytes("rsa-relaxed-simple"),
    "next\t\tcolumn", "next column");
  const report = await verify(message);
  assertStatuses(report, ["invalid"]);
  assert.equal(report.signatures[0].bodyHashMatches, false);
});

test("duplicate headers are selected bottom-up", async () => {
  const original = fixtureBytes("last-duplicate");
  const unsignedChange = replace(original, "X-Trace: older", "X-Trace: replaced");
  assertStatuses(await verify(unsignedChange), ["valid"]);
  const signedChange = replace(original, "X-Trace: newer", "X-Trace: replaced");
  assertStatuses(await verify(signedChange), ["invalid"]);
});

test("oversigning detects insertion of an extra or previously absent header", async () => {
  const original = fixtureBytes("oversigned");
  for (const header of ["X-Trace: inserted\r\n", "X-Missing: inserted\r\n"]) {
    const changed = Buffer.concat([Buffer.from(header), original]);
    assertStatuses(await verify(changed), ["invalid"]);
  }
});

test("a signed body prefix leaves an appended suffix unprotected and warns", async () => {
  const original = fixtureBytes("appended-body");
  const changed = replace(original, "Unsigned suffix.", "Different unsigned text.");
  for (const message of [original, changed]) {
    const report = await verify(message);
    assertStatuses(report, ["valid"]);
    assert.match(JSON.stringify(report.signatures[0].warnings), /body|unsigned|partial|length/i);
  }
  assertStatuses(await verify(replace(original, "Signed prefix.", "Changed prefix.")),
    ["invalid"]);
});

test("one bad signature does not hide another good signature", async () => {
  const message = replace(fixtureBytes("multiple"), "b=", "b=A");
  const report = await verify(message);
  assert.notEqual(report.signatures[0].status, "valid");
  assert.equal(report.signatures[1].status, "valid");
});

test("a signature covering another signature authenticates that header", async () => {
  const original = fixtureBytes("signed-signature");
  const changed = replace(original, "a=ed25519-sha256", "a=ed25519-sha257");
  const report = await verify(changed);
  assert.equal(report.signatures[0].status, "invalid");
  assert.notEqual(report.signatures[1].status, "valid");
});

test("expiration is evaluated against the explicit verification clock", async () => {
  const message = fixtureBytes("expires");
  assertStatuses(await verify(message, fixtures.keys, fixtures.expirationTime - 1), ["valid"]);
  assertStatuses(await verify(message, fixtures.keys, fixtures.expirationTime + 1), ["expired"]);
  assertStatuses(await verify(fixtureBytes("rsa-relaxed-relaxed"), fixtures.keys, 4102444800),
    ["valid"]);
});

test("malformed signature tags produce reports rather than rejected promises", async () => {
  const original = fixtureBytes("rsa-relaxed-relaxed");
  for (const [before, after] of [
    ["b=", "b=!"], ["bh=", "bh=!"], ["v=1;", "v=1; v=1;"],
    ["d=example.test;", ""], ["s=rsa;", ""], ["h=", "h=\u0000"],
  ]) {
    const report = await verify(replace(original, before, after));
    assert.equal(report.signatures.length, 1);
    assert.notEqual(report.signatures[0].status, "valid", `${before} → ${after}`);
    assert.ok(report.signatures[0].explanation);
  }
});
