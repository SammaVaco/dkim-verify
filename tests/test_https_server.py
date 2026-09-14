import importlib.util
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request


SITE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("serve_https", SITE / "scripts/serve_https.py")
serve_https = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(serve_https)


class HttpsServerTests(unittest.TestCase):
    def test_trusted_tls_serves_only_the_site(self):
        with tempfile.TemporaryDirectory() as directory:
            certificate = Path(directory) / "cert.pem"
            private_key = Path(directory) / "key.pem"
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-days", "1", "-subj", "/CN=localhost",
                "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
                "-keyout", str(private_key), "-out", str(certificate),
            ], check=True, capture_output=True)
            with serve_https.create_server(certificate, private_key, "127.0.0.1", 0) as server:
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    base = f"https://127.0.0.1:{server.server_port}"
                    context = ssl.create_default_context(cafile=str(certificate))
                    opener = urllib.request.build_opener(
                        urllib.request.ProxyHandler({}),
                        urllib.request.HTTPSHandler(context=context),
                    )
                    for filename in ("index.html", "dkim.js", "keys.json"):
                        with opener.open(f"{base}/{filename}", timeout=5) as response:
                            self.assertEqual(response.read(), (SITE / filename).read_bytes())
                    with self.assertRaises(urllib.error.HTTPError) as failure:
                        opener.open(f"{base}/../original_msg.eml", timeout=5)
                    self.assertEqual(failure.exception.code, 404)
                finally:
                    server.shutdown()
                    thread.join(timeout=5)

    def test_rejects_private_keys_inside_the_served_directory(self):
        with self.assertRaisesRegex(ValueError, "outside"):
            serve_https.create_server("unused.pem", SITE / "private-key.pem", "127.0.0.1", 0)


if __name__ == "__main__":
    unittest.main()
