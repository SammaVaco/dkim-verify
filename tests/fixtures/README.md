# Independent DKIM fixtures

`vectors.json` contains synthetic messages signed and independently verified with
Python's `dkimpy`. No real email or provider key appears in these fixtures.
`rsa-test-private.pem` is an intentionally public, test-only private key;
the Ed25519 test seed is fixed in the generator. Never use either for real mail.

Regenerate from the repository root:

```sh
python -m pip install dkimpy cryptography pynacl
python dkim-verifier/tests/fixtures/generate-fixtures.py
node --test dkim-verifier/tests/vectors.test.mjs
```

The saved RSA key and fixed signing time make regeneration reproducible.
Tests set an explicit verification time, so the expiring fixture does not make
the test suite age out. All baseline signatures must pass dkimpy verification
before the generator writes the fixture JSON. JavaScript tests then independently
check those signatures and deliberate mutations using the browser verifier.
