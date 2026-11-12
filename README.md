# Signet

Signet is a messaging protocol for people and their software agents. It keeps ordinary email addresses and changes what stands behind them: each address resolves to an identity key and a set of certified clients, strangers can send only a small typed request, conversations are end-to-end encrypted MLS groups, and an agent's authority is stated in signed grants the counterparty can check. Plain email keeps working in both directions.

The specification is [`docs/signet-protocol-v0.txt`](docs/signet-protocol-v0.txt). Where this code falls short of it, the gap is listed in [`packages/lib/ERRATA.md`](packages/lib/ERRATA.md).

## Packages

| Package | What it is |
| --- | --- |
| [`packages/lib`](packages/lib) | The protocol: identities and account logs, the directory, transparency proofs, requests, threads, intents and grants, delivery, and the client |
| [`packages/mls`](packages/mls) | The native core in Rust: MLS (RFC 9420, via OpenMLS), ECVRF (RFC 9381) and SPAKE2 pairing, as a Node addon |
| [`packages/server`](packages/server) | The home server, transparency log, Privacy Pass issuer and OHTTP relay |
| [`packages/client`](packages/client) | The `signet` command-line client |

## Running it

You need Node 24, pnpm and a Rust toolchain.

```bash
pnpm install
pnpm build:mls
pnpm demo
```

`pnpm demo` runs two domains, a log, an issuer and a relay in one process and walks through first contact, a thread, and the attacks Signet catches. `pnpm disclosure-demo` shows one agent asking a colleague's agent for information the colleague has to approve.

Tests run per file, for example `pnpm jest packages/server/src/__tests__/server.test.ts`. `pnpm typecheck` checks all three TypeScript packages.
