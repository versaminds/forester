# SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
# Copyright © 2026 VersaMinds
"""A TLS server that speaks one TLS version only and answers the first LDAP
request with an empty success: enough to see whether Forester connects with
that version. For tlsOlderThan12IsRefused (TESTING.md, step 3).

    python3 TestDirectory/old_tls_server.py 14611 1.1
    python3 TestDirectory/old_tls_server.py 14612 1.2

Its self-signed certificate is made in TestDirectory/.run/oldtls the first
time. Needs Python with an OpenSSL that still speaks TLS 1.1 (Homebrew's).
"""
import os
import socket
import ssl
import subprocess
import sys
import threading
import warnings

warnings.simplefilter("ignore")
port, version = int(sys.argv[1]), sys.argv[2]
folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".run", "oldtls")
os.makedirs(folder, exist_ok=True)
cert, key = os.path.join(folder, "cert.pem"), os.path.join(folder, "key.pem")
if not os.path.exists(cert):
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
                    "-days", "7", "-subj", "/CN=localhost"], check=True, capture_output=True)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.set_ciphers("DEFAULT@SECLEVEL=0")
only = {"1.1": ssl.TLSVersion.TLSv1_1, "1.2": ssl.TLSVersion.TLSv1_2}[version]
context.minimum_version = context.maximum_version = only
context.load_cert_chain(cert, key)

# SearchResultDone, success, for message 1: what the first request gets.
DONE = bytes.fromhex("300c02010165070a010004000400")

listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", port))
listener.listen(5)
print(f"TLS {version} only on 127.0.0.1:{port}", flush=True)


def serve(connection):
    try:
        tls = context.wrap_socket(connection, server_side=True)
        print("handshake:", tls.version(), flush=True)
        tls.recv(1000)
        tls.sendall(DONE)
        tls.recv(1000)
        tls.close()
    except Exception as error:
        print("handshake refused:", error, flush=True)
        connection.close()


while True:
    accepted, _ = listener.accept()
    threading.Thread(target=serve, args=(accepted,), daemon=True).start()
