# SE050 Simulator

A software simulator for the NXP SE050 secure element, implementing the full I2C / T=1 / APDU protocol stack. Designed as a drop-in replacement for real SE050 hardware in development and testing environments.

## Features

### Cryptographic Operations
- **ECC**: Key generation, ECDSA sign/verify for NIST P-224, P-256, P-384 curves
- **EdDSA**: Ed25519 key generation, sign/verify
- **RSA**: 1024–4096 bit key generation, PKCS1v1.5 and PSS sign/verify, PKCS1v1.5 and OAEP encrypt/decrypt
- **AES**: Key write/generate, AES-CBC encrypt/decrypt (oneshot and multi-step)
- **ECDH**: Diffie-Hellman shared secret for P-224, P-256, P-384
- **Digest**: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 (oneshot and multi-step)
- **RNG**: Hardware-quality random number generation

### Object Management
- Persistent object store (JSON file on disk)
- WriteBinary, ReadObject, CheckObjectExists, DeleteSecureObject
- ReadIDList, ReadType, ReadSize
- UserID, Counter objects
- Crypto object lifecycle (Create, List, Delete)

### Protocol Stack
- **T=1 protocol** (ISO 7816-3): Frame parsing/building, CRC-16 X25, S-frames (InterfaceSoftReset, GetATR, Resync), I-frame sequencing, multi-frame chaining
- **APDU** (ISO 7816-4): Full command/response parsing with TLV encoding
- **Transport**: In-process mock I2C (for Rust driver tests) and TCP server (for C/SDK integration)

## Quick Start

### Run the Rust integration tests

```bash
docker build -t se050-sim .
docker run se050-sim
```

This builds the simulator and runs 23 tests (9 unit + 14 integration) against the [nxp-se050](https://github.com/imrank03/nxp-se050) Rust driver.

### Run the wolfCrypt test suite

```bash
docker build -f Dockerfile.wolfcrypt -t se050-sim-wolfcrypt .
docker run se050-sim-wolfcrypt
```

This builds a full integration with wolfSSL and the NXP Plug&Trust SDK, then runs the wolfCrypt cryptographic test suite against the simulator. See [wolfCrypt Integration](#wolfcrypt-integration) for details.

## Architecture

```
┌─────────────────────────────────────┐
│  Application / Test Suite           │
│  (Rust driver or C SDK + wolfSSL)   │
└────────────┬────────────────────────┘
             │  I2C or TCP
┌────────────▼────────────────────────┐
│  T=1 Responder (t1.rs)             │
│  Frame parsing, CRC-16, S-frames   │
└────────────┬────────────────────────┘
             │
┌────────────▼────────────────────────┐
│  APDU Dispatch (dispatch.rs)        │
│  Routes (CLA, INS, P1, P2)         │
└────────────┬────────────────────────┘
             │
┌────────────▼────────────────────────┐
│  Handlers                           │
│  session, management, ec, rsa,      │
│  aes, digest, object_mgmt,         │
│  crypto_obj                         │
└────────────┬────────────────────────┘
             │
┌────────────▼────────────────────────┐
│  Object Store (JSON persistence)    │
└─────────────────────────────────────┘
```

### Two transport modes

1. **In-process mock I2C** (`Se050Simulator` struct) — implements `embedded_hal::blocking::i2c::{Read, Write}` for direct use with the Rust `nxp-se050` driver
2. **TCP server** (`tcp_server` binary) — listens on port 8050, serves T=1 frames over TCP for use with the NXP Plug&Trust C SDK

## Project Structure

```
SE050Sim/
├── Dockerfile                 Rust driver integration tests
├── Dockerfile.wolfcrypt       wolfCrypt test suite integration
├── patches/
│   └── apply.sh               Driver bug patches for nxp-se050
├── se050-sim/
│   ├── Cargo.toml
│   ├── src/
│   │   ├── lib.rs
│   │   ├── transport.rs       Mock I2C (embedded_hal traits)
│   │   ├── t1.rs              T=1 protocol responder
│   │   ├── apdu.rs            APDU parser + response builder
│   │   ├── tlv.rs             TLV encoder/decoder
│   │   ├── dispatch.rs        Command routing
│   │   ├── bin/
│   │   │   └── tcp_server.rs  TCP server binary
│   │   ├── handlers/
│   │   │   ├── session.rs     SELECT applet
│   │   │   ├── management.rs  GetVersion, GetRandom, etc.
│   │   │   ├── object_mgmt.rs Object CRUD operations
│   │   │   ├── crypto_obj.rs  Crypto object lifecycle
│   │   │   ├── ec.rs          ECC operations (P-224/256/384, Ed25519)
│   │   │   ├── rsa.rs         RSA operations
│   │   │   ├── aes.rs         AES operations
│   │   │   └── digest.rs      Hash operations
│   │   └── object_store/
│   │       ├── mod.rs          HashMap + JSON persistence
│   │       └── types.rs        SecureObject enum
│   └── tests/
│       └── integration.rs     Tests using the nxp-se050 driver
└── wolfcrypt-test/
    ├── i2c_a7.c               Custom PAL: TCP socket transport
    ├── se05x_reset.c           No-op reset stub for Docker
    ├── main.c                  wolfCrypt test wrapper with SE050 init
    ├── CMakeLists.txt          SDK library build
    ├── patch_ftr.py            Enable EC curve features in SDK
    └── run_test.sh             Test runner script
```

## wolfCrypt Integration

The simulator can run the [wolfSSL](https://www.wolfssl.com/) wolfCrypt test suite, validating SE050 crypto operations through the full NXP Plug&Trust middleware stack.

### How it works

```
wolfCrypt test → SSS API → Se05x APDU layer → smCom → T1oI2C → PAL I2C
                                                                    │
                                                            TCP socket
                                                                    │
                                                          se050-sim-server
```

A custom `i2c_a7.c` replaces the NXP SDK's I2C platform layer with TCP socket calls. The simulator's TCP server (`tcp_server`) accepts connections on port 8050 and processes T=1 frames identically to how it handles the Rust driver.

### Test results

| Category | Tests | Status |
|----------|-------|--------|
| SHA (1/224/256/384/512), SHA-3 | 6 | Pass |
| RANDOM | 1 | Pass |
| SHAKE128, SHAKE256, Hash | 3 | Pass |
| HMAC (SHA/224/256/384/512/SHA3) | 6 | Pass |
| HMAC-KDF, PRF, TLSv1.3 KDF | 3 | Pass |
| GMAC, Chacha, POLY1305, ChaPoly | 4 | Pass |
| AES, AES192, AES256, AES-CBC, AES-GCM | 5 | Pass |
| DH, PWDBASED | 2 | Pass |
| macro, error, MEMORY, base64, asn | 5 | Pass |
| ECC (P-224/P-256 fully pass, P-384 vector WIP) | 1 | Fail* |
| RSA | — | Skipped† |

\* ECC keygen, ECDSA sign/verify, ECDH, key import, and test vectors all pass for P-224 and P-256. P-384 keygen/sign/verify/ECDH pass but the FIPS 186-3 test vector (SHA-1 hash on P-384) fails. See [Known Issues](#known-issues).

† RSA disabled due to a known wolfCrypt SE050 RSA bug.

### Building manually

If you want to build outside Docker:

1. **Build the simulator TCP server:**
   ```bash
   cd se050-sim
   cargo build --release --bin tcp_server
   ```

2. **Clone and build the NXP Plug&Trust SDK:**
   ```bash
   git clone https://github.com/NXP/plug-and-trust.git simw-top
   # Replace PAL I2C with TCP transport
   cp wolfcrypt-test/i2c_a7.c simw-top/hostlib/hostLib/platform/linux/i2c_a7.c
   cp wolfcrypt-test/se05x_reset.c simw-top/hostlib/hostLib/platform/rsp/se05x_reset.c
   # Patch EC curve features
   python3 wolfcrypt-test/patch_ftr.py simw-top/fsl_sss_ftr.h
   # Add build file and build
   cp wolfcrypt-test/CMakeLists.txt simw-top/CMakeLists.txt
   cd simw-top && mkdir build && cd build
   cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS="-fPIC" \
     -DPTMW_Applet=SE05X_C -DPTMW_SE05X_Auth=None \
     -DPTMW_SMCOM=T1oI2C -DPTMW_HostCrypto=None -DPTMW_Host=LinuxLike
   cmake --build . -j$(nproc)
   ```

3. **Build wolfSSL with SE050 support:**
   ```bash
   git clone https://github.com/wolfSSL/wolfssl.git
   cd wolfssl && ./autogen.sh
   ./configure --with-se050=/path/to/simw-top \
     --enable-keygen --enable-cryptocb --enable-ecc \
     --enable-ed25519 --enable-curve25519 \
     --enable-sha224 --enable-sha384 --enable-sha512 \
     --disable-rsa --disable-examples --enable-crypttests \
     CFLAGS="-DWOLFSSL_SE050_INIT" \
     LDFLAGS="-L/path/to/simw-top/build/sss"
   make -j$(nproc) && make install
   ```

4. **Run:**
   ```bash
   # Terminal 1: start the simulator
   ./se050-sim/target/release/tcp_server

   # Terminal 2: run tests
   export SE050_SIM_HOST=127.0.0.1
   export SE050_SIM_PORT=8050
   ./wolfcrypt_se050_test
   ```

## NXP Driver Patches

The [nxp-se050](https://github.com/imrank03/nxp-se050) Rust driver has several bugs that are patched automatically (see `patches/apply.sh`):

| Bug | Fix |
|-----|-----|
| `embedded-hal = "*"` resolves to 1.0 (needs 0.2) | Pin to `"0.2"` |
| `CApduByteIterator` panics on empty body deque | Skip body area when empty |
| `CApduByteIterator` panics on empty TLV data | Don't push empty data slices |
| `SimpleTlv` header capacity (3) too small for extended TLV | Increase to 4 |
| Response buffers too small (16 bytes) for hash/RSA | Increase to 260 bytes |

## Known Issues

- **ECC test (P-384 vector)**: The wolfCrypt ECC test fails at `ecc_test_vector 48` — a P-384 ECDSA test vector using a SHA-1 hash (20 bytes). ECC keygen, sign, verify, ECDH, key import, and test vectors all pass for P-224 and P-256. The P-384 prehash verification with a non-native hash size (SHA-1 on a SHA-384 curve) returns false. Under investigation.

- **RSA via wolfCrypt**: There is a known bug in wolfCrypt's SE050 RSA integration. RSA works correctly through the Rust driver tests.

- **SCP03**: Secure Channel Protocol 03 is not implemented. The simulator operates in plain (unauthenticated) mode only.

- **P-384 test vector**: The FIPS 186-3 P-384 test vector uses SHA-1 (20-byte hash) with a P-384 key. The simulator's prehash verify returns false for this combination. P-384 keygen, sign, verify, and ECDH all work correctly with native-sized hashes.

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
