# @signet/mls

Signet's native crypto, with Node bindings via napi-rs:

- **MLS:** RFC 9420 groups on [OpenMLS](https://github.com/openmls/openmls) (cipher suite `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`).
- **VRF:** ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381) on curve25519-dalek, in `src/vrf.rs`, checked against the RFC's test vector. It indexes the transparency log.
- **Pairing:** SPAKE2 over Ed25519 from the RustCrypto `spake2` crate (the magic-wormhole construction), as the `Pake` class. A new client and its owner's device run it over a pairing code's secret part.

- `src/core.rs` is plain Rust with no binding types, so the same core can back a Swift/Kotlin build (UniFFI) for the iOS app later.
- `src/lib.rs` is the Node addon. `packages/lib/src/mls.ts` is its only caller.

## Design

- **Functional state.** Every call takes the client's serialized OpenMLS key store and returns the new one. If a call fails, or a commit is only previewed, the caller's copy is untouched.
- **Signet decides membership, not the core.** `peekWelcome` and `process(..., apply=false)` report every credential a welcome or commit carries. @signet/lib checks each one against its owner's signed log, then joins or applies the commit.
- **Leaves use the client's certified Ed25519 key**, so an MLS member is exactly a certified Signet client.
- **Last-resort key packages** (RFC 9420 §17.3) can be reused, so draining a client's one-time packages can't lock it out.
- **Padding:** messages are padded to 256-byte blocks so sizes leak less.
- **Exporter:** `exportSecret` derives per-epoch sealed-sender delivery tokens.

## Build

Requires a Rust toolchain (1.85+).

```bash
pnpm build:mls    # cargo build --release, then copies the library to signet_mls.node
```

@signet/lib loads `packages/mls/signet_mls.node`, or the path in `SIGNET_MLS_ADDON`. Bundled apps must ship the `.node` file and set that variable.

## Audit status

OpenMLS is the most widely deployed open-source Rust MLS implementation, but check its current audit status before relying on it. This crate's own code, roughly 400 lines, hasn't been reviewed.
