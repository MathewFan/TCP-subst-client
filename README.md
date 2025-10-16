# TCP Substitution Cipher Client (C, Linux/WSL)

## Build
```bash
sudo apt update && sudo apt install -y build-essential libssl-dev python3
make

## File Descriptions:
**/ src/net.c: Dial TCP, read_full/write_full (handle short reads/writes), read/write framed messages, endian conversions (htonl/ntohl, etc.).

src/proto.c: Implements the state machine (auth→map→ciphertext), calls OpenSSL HMAC, applies the cipher map, prints plaintext, sends ACKs, treats EOF as success.

src/cipher.c: Tiny, hot path byte-mapping decrypt function.

include/common.h: Shared types (header struct, enums), function prototypes.

test/mock_server.py: Local server to exercise the flow (issues challenge, sends map, encrypts plaintext and streams it).
**/
