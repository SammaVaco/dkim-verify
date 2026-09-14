import argparse
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import ssl


SITE = Path(__file__).resolve().parents[1]


def create_server(certificate, private_key, bind, port):
    if Path(private_key).resolve().is_relative_to(SITE):
        raise ValueError("Keep the TLS private key outside the served dkim-verifier directory")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, private_key)
    handler = partial(SimpleHTTPRequestHandler, directory=str(SITE))
    server = ThreadingHTTPServer((bind, port), handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def main():
    parser = argparse.ArgumentParser(description="Serve the DKIM verifier over HTTPS using your certificate.")
    parser.add_argument("--cert", required=True, help="Certificate PEM trusted by the browser")
    parser.add_argument("--key", required=True, help="Private-key PEM outside the site directory")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    options = parser.parse_args()
    try:
        server = create_server(options.cert, options.key, options.bind, options.port)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    with server:
        print(f"Serving {SITE} over HTTPS on {options.bind}:{server.server_port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
