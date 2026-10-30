# Bounded TCP substitution client

A C17 systems project about correctness under hostile TCP fragmentation: explicit wire encoding, a stateful protocol, binary-safe HMAC challenges, and bounded network I/O. OpenSSL supplies HMAC; the substitution mapping is a teaching cipher. This protocol does **not** provide TLS, authenticated servers, or confidential transport.

## Run

Install a C compiler, pkg-config, Python 3 and OpenSSL development headers. On macOS set `PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig"`.

```sh
make
export SUBST_SECRET='local-demo-secret'
python3 test/mock_server.py --fragment 3
# In another terminal with the same SUBST_SECRET:
SUBST_STATS=1 ./subst_client 127.0.0.1 5555 demo > decoded.bin
make test
make sanitize
```

The fixture verifies HMAC and streams a greeting followed by every possible byte value. It binds only to loopback. Environment credentials avoid exposing the secret in command arguments; the legacy final argument remains compatible. Environment variables are not a secrets vault.

## Wire contract and invariants

Every frame is a 12-byte big-endian header: magic `0x53554253` (u32), version `1` (u16), type (u16), body length (u32). Bodies are capped at 1 MiB before allocation. The client accepts exactly this sequence:

1. AUTH_CHALLENGE (1): 1–1024 arbitrary bytes, including NUL.
2. AUTH_RESPONSE (2): lowercase hex HMAC-SHA256, key=secret, message=`username|salt|secret` (raw salt bytes).
3. CIPHER_MAP (3): 256 bytes forming a permutation; map[cipher]=plain.
4. CIPHERTEXT (4): any bytes, decoded in place; one empty ACK (5) after stdout accepts the chunk.
5. Clean frame-boundary EOF ends the stream successfully. Truncation, unexpected states and failed writes exit nonzero.

`SUBST_TIMEOUT_MS` defaults to 5000 (allowed 10–600000). One monotonic deadline covers an entire network frame, so a peer cannot reset its budget by dripping bytes. Connect attempts share a deadline after DNS resolution. DNS resolution and writes to a blocking stdout destination are not covered by that network deadline. An ACK means stdout accepted bytes, not that a downstream file was fsynced. On later failure, earlier stdout bytes may already exist: consumers should check exit status before publishing output.

`SUBST_STATS=1` emits frames, plaintext bytes and ACK counts to stderr, preserving binary-clean stdout. `frames` counts parsed incoming frames, including control frames. Plaintext byte and ACK counters advance only after successful output and ACK; diagnostics do not include secrets. Empty server ACK frames are tolerated during streaming.

## Verification

Real socket tests cover three-byte fragmentation, all 256 byte values, binary salts, malformed headers, oversized allocation requests, truncation, invalid permutations, early/duplicate frames, and slow-drip deadlines. Linux and macOS CI run the same suite with AddressSanitizer and UndefinedBehaviorSanitizer. These are controlled fault tests, not an Internet security audit or performance claim.
