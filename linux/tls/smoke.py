#!/usr/bin/env python3
"""Verify the installed Classic TLS closure and real trusted/untrusted HTTPS."""
import argparse
import http.server
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading

PREFIX = Path('/opt/atrinik/tls')
ROOT = Path(__file__).resolve().parent


def run(*argv, **kwargs):
    return subprocess.run(argv, check=True, **kwargs)


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'Classic TLS fixture\n'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class Server(http.server.HTTPServer):
    """Keep fixture thread errors visible to the main acceptance result."""
    def __init__(self, *args):
        super().__init__(*args)
        self.allow_trust_rejection = False
        self.expected_trust_rejections = 0
        self.unexpected_errors = []

    def handle_error(self, request, client_address):
        error = sys.exception()
        # The negative-CA client aborts before sending an HTTP request. Depending
        # on TLS scheduling, the server sees its alert or a reset/broken pipe.
        expected = isinstance(error, (BrokenPipeError, ConnectionResetError)) or (
            isinstance(error, ssl.SSLError) and error.reason in (
                'TLSV1_ALERT_UNKNOWN_CA', 'SSLV3_ALERT_BAD_CERTIFICATE'))
        if self.allow_trust_rejection and expected:
            self.expected_trust_rejections += 1
        else:
            self.unexpected_errors.append(type(error).__name__)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=ROOT / 'manifest.json')
    args = parser.parse_args()
    expected = json.loads(args.manifest.read_text())
    installed = json.loads((PREFIX / 'share/atrinik/classic-tls.json').read_text())
    if expected != installed:
        raise RuntimeError('TLS manifest mismatch')
    environment = dict(os.environ)
    for name in ('LD_LIBRARY_PATH', 'OPENSSL_CONF', 'OPENSSL_MODULES', 'CMAKE_PREFIX_PATH'):
        environment.pop(name, None)
    environment['PKG_CONFIG_PATH'] = str(PREFIX / 'lib/pkgconfig')
    flags = subprocess.check_output(['pkg-config', '--cflags', '--libs', 'openssl', 'libcurl'], env=environment, text=True).split()
    with tempfile.TemporaryDirectory(prefix='classic-tls-smoke-') as tmp:
        work = Path(tmp)
        binary = work / 'smoke'
        run('cc', '-std=c17', '-Wall', '-Wextra', '-Werror', str(ROOT / 'smoke.c'), '-o', str(binary),
            *flags, '-ldl', f'-Wl,-rpath,{PREFIX}/lib', env=environment)
        run(str(binary), env=environment)
        for name in ('server', 'untrusted'):
            run(str(PREFIX / 'bin/openssl'), 'req', '-new', '-x509', '-newkey', 'rsa:2048', '-nodes',
                '-keyout', str(work / f'{name}.key'), '-out', str(work / f'{name}.pem'), '-days', '1',
                '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Python's distro SSL module remains on its own TLS provider. Successful
        # HTTPS also proves interoperability with the isolated application cohort.
        server = Server(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(work / 'server.pem', work / 'server.key')
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f'https://localhost:{server.server_port}/'
            run(str(binary), url, str(work / 'server.pem'), 'trusted', env=environment)
            server.allow_trust_rejection = True
            run(str(binary), url, str(work / 'untrusted.pem'), 'untrusted', env=environment)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        if thread.is_alive() or server.unexpected_errors:
            raise RuntimeError(f'HTTPS fixture failed: {server.unexpected_errors}')
    print(json.dumps({'classic_tls': True, 'public_peer_api': True, 'provider_closure': True,
                      'https_trusted': True, 'https_untrusted_rejected': True,
                      'expected_server_trust_rejections': server.expected_trust_rejections}))


if __name__ == '__main__':
    main()
