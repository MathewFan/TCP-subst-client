#!/usr/bin/env python3
import socket, struct, threading, os

MAGIC = 0x53554253
VERSION = 1
AUTH_CHALLENGE, AUTH_RESPONSE, CIPHER_MAP, CIPHERTEXT, ACK = 1,2,3,4,5

def send_frame(conn, t, body=b""):
    hdr = struct.pack("!IHHI", MAGIC, VERSION, t, len(body))
    conn.sendall(hdr + body)

def recv_frame(conn):
    hdr = conn.recv(12)
    if len(hdr) < 12: return None, None
    magic, ver, t, n = struct.unpack("!IHHI", hdr)
    if magic != MAGIC or ver != VERSION: return None, None
    body = b""
    while len(body) < n:
        chunk = conn.recv(n - len(body))
        if not chunk: break
        body += chunk
    return t, body

def serve_client(conn, addr):
    # Step 1: challenge
    salt = b"course-salt"
    send_frame(conn, AUTH_CHALLENGE, salt)

    # Step 2: receive auth response (we won't verify for the mock)
    t, body = recv_frame(conn)
    assert t == AUTH_RESPONSE

    # Step 3: send substitution map (Caesar shift by 3 for demo)
    m = bytes(((i - 3) % 256 for i in range(256)))
    send_frame(conn, CIPHER_MAP, m)

    # Step 4: send ciphertext chunks
    texts = [b"Hello, world!\n", b"Cipher text 1\n", b"Cipher text 2\n"]
    # Encrypt by inverse of map: plain p → cipher c where m[c]=p
    inv = [0]*256
    for c,p in enumerate(m): inv[p]=c
    for msg in texts:
        enc = bytes([inv[x] for x in msg])
        send_frame(conn, CIPHERTEXT, enc)
        # expect ACK (optional)
        t,_ = recv_frame(conn)
        if t != ACK: break
    conn.close()

def main():
    HOST, PORT = "127.0.0.1", 5555
    with socket.create_server((HOST, PORT), reuse_port=True) as s:
        print(f"Mock server on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=serve_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()
