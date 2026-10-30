#!/usr/bin/env python3
"""Local protocol fixture. Substitution is a teaching cipher, not encryption."""
import argparse
import hashlib
import hmac
import os
import socket
import struct

MAGIC = 0x53554253
VERSION = 1
AUTH_CHALLENGE, AUTH_RESPONSE, CIPHER_MAP, CIPHERTEXT, ACK = range(1, 6)


def read_exact(conn, n):
    result = bytearray()
    while len(result) < n:
        chunk = conn.recv(n - len(result))
        if not chunk:
            raise EOFError("truncated frame")
        result.extend(chunk)
    return bytes(result)


def recv_frame(conn):
    magic, version, kind, size = struct.unpack("!IHHI", read_exact(conn, 12))
    if magic != MAGIC or version != VERSION or size > 1024 * 1024:
        raise ValueError("invalid header")
    return kind, read_exact(conn, size)


def send_frame(conn, kind, body=b"", fragment=0):
    wire = struct.pack("!IHHI", MAGIC, VERSION, kind, len(body)) + body
    width = fragment or len(wire)
    for offset in range(0, len(wire), width):
        conn.sendall(wire[offset:offset + width])


def serve_client(conn, username, secret, fragment=0):
    conn.settimeout(5)
    salt = os.urandom(32)
    send_frame(conn, AUTH_CHALLENGE, salt, fragment)
    kind, response = recv_frame(conn)
    expected = hmac.new(secret, username.encode() + b"|" + salt + b"|" + secret,
                        hashlib.sha256).hexdigest().encode()
    if kind != AUTH_RESPONSE or not hmac.compare_digest(response, expected):
        raise ValueError("authentication failed")
    mapping = bytes((i - 3) % 256 for i in range(256))
    send_frame(conn, CIPHER_MAP, mapping, fragment)
    for plain in (b"Hello, world!\n", bytes(range(256))):
        encrypted = bytes((byte + 3) % 256 for byte in plain)
        send_frame(conn, CIPHERTEXT, encrypted, fragment)
        if recv_frame(conn) != (ACK, b""):
            raise ValueError("missing acknowledgement")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=5555)
    parser.add_argument("--user", default="demo")
    parser.add_argument("--fragment", type=int, default=0)
    args = parser.parse_args()
    secret = os.environ.get("SUBST_SECRET")
    if not secret or args.fragment < 0:
        parser.error("set SUBST_SECRET and use a nonnegative fragment size")
    with socket.create_server(("127.0.0.1", args.port)) as server:
        print(f"Fixture listening on 127.0.0.1:{args.port}", flush=True)
        # Sequential and bounded: a stalled peer cannot create unbounded threads.
        while True:
            conn, _ = server.accept()
            with conn:
                try:
                    serve_client(conn, args.user, secret.encode(), args.fragment)
                except (OSError, EOFError, ValueError) as error:
                    print(type(error).__name__ + ": " + str(error), flush=True)


if __name__ == "__main__":
    main()
