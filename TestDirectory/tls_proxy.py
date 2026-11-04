#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
# Copyright © 2026 VersaMinds
"""TLS front-end for the test slapd.

Apple's slapd only takes a TLS identity from a keychain, and a test fixture
should not install one. This proxy terminates TLS itself and forwards plain
LDAP to slapd:

  --ldaps PORT     TLS from the first byte (ldaps://)
  --plain PORT     plain LDAP that answers the StartTLS extended operation
                   (1.3.6.1.4.1.1466.20037) and upgrades the client in place

Only the first request on a plain connection is inspected; everything else is
copied byte for byte, so slapd sees the client's real requests.
"""
import argparse
import asyncio
import ssl

STARTTLS_OID = b"1.3.6.1.4.1.1466.20037"


def ber_length(buf, i):
    first = buf[i]
    if first < 0x80:
        return first, i + 1
    n = first & 0x7F
    return int.from_bytes(buf[i + 1:i + 1 + n], "big"), i + 1 + n


async def read_message(reader):
    head = await reader.readexactly(2)
    if head[1] & 0x80:
        head += await reader.readexactly(head[1] & 0x7F)
    length, _ = ber_length(head, 1)
    return head + await reader.readexactly(length)


def starttls_message_id(msg):
    """The messageID if msg is a StartTLS ExtendedRequest, else None."""
    _, i = ber_length(msg, 1)
    if msg[i] != 0x02:
        return None
    id_len = msg[i + 1]
    message_id = msg[i + 2:i + 2 + id_len]
    op = i + 2 + id_len
    if msg[op] == 0x77 and STARTTLS_OID in msg[op:]:
        return message_id
    return None


def starttls_response(message_id):
    oid = STARTTLS_OID
    result = b"\x0a\x01\x00\x04\x00\x04\x00" + b"\x8a" + bytes([len(oid)]) + oid
    op = b"\x78" + bytes([len(result)]) + result
    body = b"\x02" + bytes([len(message_id)]) + message_id + op
    return b"\x30" + bytes([len(body)]) + body


async def pipe(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.IncompleteReadError, ssl.SSLError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def relay(client_reader, client_writer, backend, first=b""):
    up_reader, up_writer = await asyncio.open_connection(*backend)
    if first:
        up_writer.write(first)
        await up_writer.drain()
    await asyncio.gather(pipe(client_reader, up_writer), pipe(up_reader, client_writer))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", default="127.0.0.1:10388")
    ap.add_argument("--plain", type=int, default=10389)
    ap.add_argument("--ldaps", type=int, default=10636)
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    args = ap.parse_args()
    host, port = args.backend.rsplit(":", 1)
    backend = (host, int(port))

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(args.cert, args.key)

    async def on_ldaps(reader, writer):
        await relay(reader, writer, backend)

    async def on_plain(reader, writer):
        try:
            first = await read_message(reader)
        except (asyncio.IncompleteReadError, ConnectionError):
            writer.close()
            return
        message_id = starttls_message_id(first)
        if message_id is None:
            await relay(reader, writer, backend, first)
            return
        writer.write(starttls_response(message_id))
        await writer.drain()
        try:
            await writer.start_tls(ctx)
        except (ssl.SSLError, ConnectionError):
            writer.close()  # the client refused our certificate
            return
        await relay(reader, writer, backend)

    async def serve():
        a = await asyncio.start_server(on_plain, "127.0.0.1", args.plain)
        b = await asyncio.start_server(on_ldaps, "127.0.0.1", args.ldaps, ssl=ctx)
        async with a, b:
            await asyncio.gather(a.serve_forever(), b.serve_forever())

    asyncio.run(serve())


if __name__ == "__main__":
    main()
