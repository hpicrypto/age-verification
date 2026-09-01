# Modular Anonymous Credential Demo

A demo implementation of an anonymous credential system in the commit-and-prove paradigm,
following the approach described in
["Vision: A Modular Framework for Anonymous Credential Systems"](https://eprint.iacr.org/2025/1981)
by A. Lehmann, A. Sidorenko, and A. Zacharakis. Revocation is implemented using the signed-pairs approach (instantiated with BBS-BP), as described in ["Comparing Privacy-Preserving Revocation for the EUDI Wallet"](https://eprint.iacr.org/2026/1824).

The concrete use case is age verification: a credential holder proves they are 18 years
old without revealing any other attribute, and without the verifier being able to track or
link individual presentations. 

A current deployed version of the demo is available at
[av-demo.hpi.de](https://av-demo.hpi.de).

## Structure

The workspace contains four main components:

```
crypto/modular-ac/   # Core cryptographic library for the commit-and-prove anonymous credential scheme
crypto/agever/       # Age-verification scheme built on modular-ac + Android UniFFI bindings
web/                 # Axum web server — issuer + verifier demo
wallet/              # Android app (Jetpack Compose) — holder demo
```

### `crypto/modular-ac`

Implements the full commit-and-prove anonymous credential scheme on BLS12-381 / BBS+ 23:

- **`Issuer`** — signs credentials using BBS+ 23, embedding a holder P-256 public key and a `rev_handle`.
- **`CommittedDisclosurePresenter`** — produces a `Presentation` composed of four
  sub-proofs:
  1. **Base proof** — PoK of BBS+ signature with selective disclosure and Pedersen
     commitments to the hidden messages.
  2. **Proof of validity** — Bulletproofs++ range proof that `nbf < today < exp` on the
     committed timestamps.
  3. **Holder-binding proof** — equality-across-groups proofs (tom256 ↔ BLS12-381) plus a
     PoK of ECDSA signature under the committed P-256 holder key.
  4. **Non-revocation proof** — credential validity via signed-pairs, PoK of a BBS+ 
     signature disclosing the current revocation epoch and Bulletproofs++ range proof 
     that `rid_lo < rev_handle < rid_hi`.
- **`CommittedDisclosureVerifier`** — verifies all four sub-proofs.

### `crypto/agever`

Implements the age-verification credential scheme on top of `modular-ac`, and exposes it
to Android via UniFFI:

- **Credential scheme** — defines a fixed schema (`header`, `above16`, `above18`) and
  provides `AgeVerIssuer`, `AgeVerPresenter`, and `AgeVerVerifier` that wire up the
  `modular-ac` primitives for the age-verification use case.
- **UniFFI bindings** — compiles to `libagever.so` (`cdylib`) and generates Kotlin
  bindings via the `uniffi-bindgen` binary.

### `web`

An Axum HTTP server that acts as both issuer and verifier in the demo flow:

| Endpoint | Role |
|---|---|
| `POST /issue` | Verify Android Key Attestation cert chain, issue a JWT credential |
| `GET /ageverification` | Create a session and display a QR code / deep-link |
| `POST /validate` | Verify a `AgeVerPresentation` ZK proof, mark session valid |
| `GET /revocation-status` | Publish the current epoch, revoked handles, and gap credential list |
| `POST /admin/revoke` | Revoke a `rev_handle`, bump the epoch, re-sign the gap list — guarded by `X-Admin-Secret` when `ADMIN_SECRET` is set |
| `GET /admin` | Browser page listing every issued credential (name, age, above16/above18, issued time, Active/Revoked) with checkboxes to select several and revoke them together |
| `POST /admin/revoke-bulk` | Form target for the `/admin` page — revokes every checked handle in one request |

The `/issue` endpoint verifies the Android StrongBox Key Attestation certificate chain
(Google EC + RSA roots) before issuing a credential, binding the credential to the
hardware-attested P-256 key of the wallet.

#### Environment variables

| Variable | Default | Description |
|---|---|---|
| `ISSUER_SECRET` | *(OS RNG)* | Exactly 32-byte ASCII string used as the seed for deterministic issuer keypair generation. If unset, the keypair is sampled from the OS RNG on every start — restarting without a fixed secret invalidates every previously-issued credential. |
| `REQUIRE_ATTEST` | `true` | Set to `false` or `0` to skip the Android StrongBox security-level check. |
| `EXTRA_TRUST_CERTS_PEM_FILE` | *(none)* | Path to a PEM file containing additional X.509 trust anchors. |
| `ADMIN_SECRET` | *(none)* | When set, required to call `POST /admin/revoke` (via the `X-Admin-Secret` header) and to view/use `/admin` and `/admin/revoke-bulk` (via HTTP Basic Auth, since a browser form can't send a custom header — username is ignored, password must match). When unset, all three are open to anyone who can reach them. |
| `SEED_REVOKED_COUNT` | `2000` | Number of synthetic revoked handles seeded at startup, so the demo starts with a realistically large gap list instead of an empty one. |


### `wallet`

An Android application (min SDK 31, target SDK 37) that:

1. Generates a P-256 key pair in the StrongBox secure element, if available.
2. Requests and stores a JWT credential from the `/issue` endpoint.
3. Updates the current status of the credential.
4. Scans a QR code from the verifier web page and submits a ZK presentation to `/validate`.

## Building and running

The following commands build and run the different components of the demo from the root of
the workspace. 

Note that the builds require a signigicant amount disk space (10-12 GB when all targets
are built) due to the dependency on the `docknetwork/crypto` suite, which includes
multiple large Rust libraries and their build artifacts. 

### Rust library and tests

```bash
# Run all crypto tests
cargo test -p modular-ac
```
**> Dependencies**:

- Rust toolchain (2024 edition)


### Web server

```bash
# Run locally (listens on :3000)
cargo run --bin web
```
**> Dependencies**:
A local OpenSSL installation is required for the web server to verify the Android Key Attestation
certificate chain. The server expects the `openssl` CLI tool to be available in the system PATH
and uses it to perform certificate parsing and chain verification.

```bash
# Build and run with Docker
docker build -t agever-demo-srv:latest .
docker run -p 3000:3000 agever-demo-srv
```

**> Dependencies**:
- Docker (for the containerized build and run)

### Android wallet
The wallet app is compatible with Android 10 and newer. You can compile the APK as follows:
```bash
cd wallet
./gradlew assembleDebug
```
**> Dependencies**:
- Android SDK 37, NDK `30.0.14904198`
- Gradle 8+ with Kotlin DSL
- JNA `5.18.1` for the UniFFI bridge
- Rust targets `aarch64-linux-android` and `x86_64-linux-android`

The gradle build should compile the Rust bindings for both `aarch64` and `x86_64` Android
targets as a part of the `buildRust` task. 

## License

See [LICENSE](LICENSE) and [NOTICE](NOTICE).
