"""Generate synthetic DKIM vectors; requires dkimpy, cryptography and pynacl."""

import base64
import json
from pathlib import Path
from unittest.mock import patch

import dkim
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from nacl.signing import SigningKey


DIRECTORY = Path(__file__).resolve().parent
SIGNING_TIME = 1609459200
VERIFY_TIME = SIGNING_TIME + 86400
EXPIRATION_TIME = SIGNING_TIME + 172800
HEADERS = (
    b"From: Alice <alice@example.test>\r\n"
    b"To: Bob <bob@example.test>\r\n"
    b"Subject: DKIM\t fixture\r\n\twith a folded subject\r\n"
    b"X-Trace: older\r\nX-Trace: newer\r\n\r\n"
)
BODY = b"Raw \xff\x80 and UTF-8 \xe2\x98\x83.\t \r\nnext\t\tcolumn \r\n\r\n"
SIGNED_HEADERS = [b"from", b"to", b"subject", b"x-trace", b"x-trace"]


class ExpiringDKIM(dkim.DKIM):
    def gen_header(self, fields, *args, **kwargs):
        fields.insert(-1, (b"x", str(EXPIRATION_TIME).encode("ascii")))
        return super().gen_header(fields, *args, **kwargs)


def generate():
    private_path = DIRECTORY / "rsa-test-private.pem"
    if not private_path.exists():
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_path.write_bytes(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    rsa_private = private_path.read_bytes()
    rsa_public = serialization.load_pem_private_key(rsa_private, None).public_key()
    public_der = rsa_public.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_pkcs1 = rsa_public.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.PKCS1,
    )
    pkcs1_record = "v=DKIM1; k=rsa; p=" + base64.b64encode(public_pkcs1).decode()
    ed_private = SigningKey(bytes(range(32)))
    private_keys = {
        "rsa-sha256": rsa_private,
        "ed25519-sha256": base64.b64encode(bytes(ed_private)),
    }
    keys = [
        {
            "domain": "example.test", "selector": "rsa",
            "record": "v=DKIM1; k=rsa; p=" + base64.b64encode(public_der).decode(),
            "sources": [{"type": "synthetic", "url": "./generate-fixtures.py"}],
        },
        {
            "domain": "example.test", "selector": "ed25519",
            "record": "v=DKIM1; k=ed25519; p="
            + base64.b64encode(bytes(ed_private.verify_key)).decode(),
            "sources": [{"type": "synthetic", "url": "./generate-fixtures.py"}],
        },
    ]

    def sign(message, modes=(b"relaxed", b"relaxed"), algorithm="rsa-sha256",
             headers=SIGNED_HEADERS, length=False, expire=False):
        signer = (ExpiringDKIM if expire else dkim.DKIM)(message)
        signer.should_not_sign = signer.should_not_sign - {b"dkim-signature"}
        with patch("dkim.time.time", return_value=SIGNING_TIME):
            signature = signer.sign(
                algorithm.split("-")[0].encode(), b"example.test",
                private_keys[algorithm], signature_algorithm=algorithm.encode(),
                canonicalize=modes, include_headers=headers, length=length,
            )
        return signature + message

    messages = {}
    for header_mode in (b"simple", b"relaxed"):
        for body_mode in (b"simple", b"relaxed"):
            name = "rsa-" + header_mode.decode() + "-" + body_mode.decode()
            messages[name] = sign(HEADERS + BODY, (header_mode, body_mode))
    messages["ed25519"] = sign(HEADERS + BODY, algorithm="ed25519-sha256")
    messages["empty-simple"] = sign(HEADERS, (b"simple", b"simple"))
    messages["empty-relaxed"] = sign(HEADERS)
    messages["last-duplicate"] = sign(HEADERS + BODY, headers=[b"from", b"x-trace"])
    messages["oversigned"] = sign(
        HEADERS + BODY, headers=SIGNED_HEADERS + [b"x-trace", b"x-missing"],
    )
    messages["partial-body"] = sign(HEADERS + b"Signed prefix.\r\n", length=True)
    messages["appended-body"] = messages["partial-body"] + b"Unsigned suffix.\r\n"
    messages["multiple"] = sign(messages["ed25519"])
    messages["signed-signature"] = sign(
        messages["ed25519"], headers=SIGNED_HEADERS + [b"dkim-signature"],
    )
    messages["expires"] = sign(HEADERS + BODY, expire=True)

    records = {
        f"{entry['selector']}._domainkey.{entry['domain']}": entry["record"].encode()
        for entry in keys
    }

    def lookup(name, timeout=5):
        return records.get(name.decode().rstrip("."))

    with patch("dkim.time.time", return_value=VERIFY_TIME):
        for name, message in messages.items():
            signature_count = message.count(b"DKIM-Signature:")
            for index in range(signature_count):
                assert dkim.DKIM(message).verify(index, dnsfunc=lookup), (name, index)
        assert dkim.verify(
            messages["rsa-relaxed-relaxed"],
            dnsfunc=lambda name, timeout=5: pkcs1_record.encode(),
        )

    fixture = {
        "description": "Synthetic, independently signed and verified with dkimpy.",
        "signingTime": SIGNING_TIME,
        "verificationTime": VERIFY_TIME,
        "expirationTime": EXPIRATION_TIME,
        "keys": keys,
        "rsaPkcs1Record": pkcs1_record,
        "messages": {
            name: base64.b64encode(message).decode() for name, message in messages.items()
        },
    }
    (DIRECTORY / "vectors.json").write_text(json.dumps(fixture, indent=2) + "\n")
    print(f"Generated and verified {len(messages)} synthetic DKIM messages.")


if __name__ == "__main__":
    generate()
