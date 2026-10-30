import hashlib
import hmac
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import threading
import time
import unittest

MAGIC = 0x53554253
BINARY = str(Path(__file__).resolve().parents[1] / 'subst_client')
SECRET = 'test-only-secret'


def exact(conn, count):
    data = b''
    while len(data) < count:
        chunk = conn.recv(count-len(data))
        if not chunk:
            raise EOFError()
        data += chunk
    return data


def frame(kind, data=b'', magic=MAGIC, version=1, length=None):
    return struct.pack('!IHHI', magic, version, kind, len(data) if length is None else length) + data


def receive(conn):
    magic, version, kind, size = struct.unpack('!IHHI', exact(conn, 12))
    assert (magic, version) == (MAGIC, 1)
    return kind, exact(conn, size)


def handshake(conn, mapping=bytes(range(256)), salt=b'salt\x00binary'):
    conn.sendall(frame(1, salt))
    kind, response = receive(conn)
    expected = hmac.new(SECRET.encode(), b'alice|' + salt + b'|' + SECRET.encode(), hashlib.sha256).hexdigest().encode()
    assert kind == 2 and hmac.compare_digest(response, expected)
    conn.sendall(frame(3, mapping))


class ProtocolTests(unittest.TestCase):
    def run_peer(self, behavior, timeout=1000):
        errors = []
        with socket.create_server(('127.0.0.1', 0)) as server:
            port = server.getsockname()[1]
            def serve():
                try:
                    with server.accept()[0] as conn:
                        conn.settimeout(2)
                        behavior(conn)
                except (BrokenPipeError, ConnectionResetError, EOFError):
                    pass
                except Exception as error:
                    errors.append(error)
            worker = threading.Thread(target=serve)
            worker.start()
            result = subprocess.run([BINARY, '127.0.0.1', str(port), 'alice'], env={**os.environ, 'SUBST_SECRET': SECRET, 'SUBST_TIMEOUT_MS': str(timeout), 'SUBST_STATS': '1'}, capture_output=True, timeout=5)
            worker.join(3)
            self.assertFalse(worker.is_alive())
            if errors:
                raise errors[0]
            return result

    def test_binary_auth_and_all_byte_values(self):
        mapping = bytes((i-3) % 256 for i in range(256))
        plain = bytes(range(256)) * 4
        encrypted = bytes((i+3) % 256 for i in plain)
        def peer(conn):
            handshake(conn, mapping)
            payload = frame(4, encrypted)
            for offset in range(0, len(payload), 3):
                conn.sendall(payload[offset:offset+3])
            self.assertEqual(receive(conn), (5, b''))
            conn.sendall(frame(4))
            self.assertEqual(receive(conn), (5, b''))
        result = self.run_peer(peer)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, plain)
        stats = json.loads(result.stderr)
        self.assertEqual(stats['plaintext_bytes'], len(plain))
        self.assertEqual(stats['acks'], 2)

    def test_invalid_headers_and_state_transitions(self):
        payloads = [frame(4, b'early'), frame(3, bytes(range(256))), frame(9), frame(1, b'x', magic=0), frame(1, b'x', version=2), frame(1), frame(1, length=2**31), frame(1, b'partial', length=20), b'partial']
        for payload in payloads:
            with self.subTest(payload=payload[:12]):
                result = self.run_peer(lambda conn: conn.sendall(payload))
                self.assertNotEqual(result.returncode, 0)

    def test_eof_before_map_is_failure(self):
        def peer(conn):
            conn.sendall(frame(1, b'hello'))
            receive(conn)
        self.assertNotEqual(self.run_peer(peer).returncode, 0)

    def test_duplicate_and_wrong_length_maps(self):
        for mapping in (b'x'*256, b'x'*255):
            def peer(conn):
                handshake(conn, mapping)
            self.assertNotEqual(self.run_peer(peer).returncode, 0)

    def test_truncated_ciphertext_is_not_clean_eof(self):
        def peer(conn):
            handshake(conn)
            conn.sendall(frame(4, b'half', length=8))
        result = self.run_peer(peer)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')

    def test_absolute_deadline_defeats_drip_feed(self):
        def peer(conn):
            for byte in frame(1, b'slow'):
                conn.sendall(bytes([byte]))
                time.sleep(.03)
        result = self.run_peer(peer, timeout=100)
        self.assertNotEqual(result.returncode, 0)

    def test_repeated_map_after_stream_start_is_rejected(self):
        def peer(conn):
            handshake(conn)
            conn.sendall(frame(3, bytes(range(256))))
        self.assertNotEqual(self.run_peer(peer).returncode, 0)

    def test_ack_failure_does_not_count_delivery(self):
        # Invalid server ACK shape is a protocol failure, not an ignored frame.
        def peer(conn):
            handshake(conn)
            conn.sendall(frame(5, b'invalid'))
        self.assertNotEqual(self.run_peer(peer).returncode, 0)


if __name__ == '__main__':
    unittest.main()
