# Signet reference implementation errata

Where the reference code (`packages/lib`, `packages/mls`, `packages/server`, `packages/client`) does not yet do what the [Signet Protocol, Version 0](../../docs/signet-protocol-v0.txt) spec requires, or takes a shortcut a production deployment can't take. The spec's own Open Issues list only protocol-level questions; gaps in this code are listed here instead.

Each entry is removed in the commit that fixes it. Severity: **high** means a deployment is insecure without the fix, **medium** means it is wrong or fragile in production, and **low** means cosmetic or a demo convenience.

## 3. Identities, clients and the account log

| Section | Spec requires | Reference does | Where | Severity |
| --- | --- | --- | --- | --- |
| 3.2 | Reject non-I-JSON input (NaN, infinities, lone surrogates) when signing or verifying | `canonicalJson` serializes NaN and infinities as `null` and lone surrogates as `\uXXXX`; an `undefined` array element produces invalid JSON | `packages/lib/src/encoding.ts` | medium |
| 3.3 | A new client generates its own keys and sends only the public halves for certification | Done for `signet pair`/`join` and `enroll-request`/`approve`. `Identity.enrollClient` and `signet add-client --out` still generate a client's keys beside the identity key, for tests and demos | `packages/lib/src/identity.ts`, `packages/client/src/cli.ts` | low |
| 3.3 | Keep the identity key in hardware-backed storage; don't export it | `Identity.export` returns the private identity key; the CLI saves it as `identity.json` on the primary device | `packages/lib/src/identity.ts`, `packages/client/src/home.ts` | medium |

## 4. Directory

| Section | Spec requires | Reference does | Where | Severity |
| --- | --- | --- | --- | --- |
| 4.9 | Colleagues see each other's views only where the domain allows it | Allowed by default (`colleaguesSeeViews` defaults to on); a deployment that doesn't want it must turn it off | `packages/server/src/server.ts` | low |

## 5. Key transparency

| Section | Spec requires | Reference does | Where | Severity |
| --- | --- | --- | --- | --- |
| 5.8 | A client rejects tree heads older than a configured bound | Tree-head age isn't checked | `packages/lib/src/client.ts` (`checkTreeHead`) | medium |
| 5 | (comment accuracy) | The log server's comment says leaves are "keyed by a hash of the address"; they are keyed by VRF index | `packages/server/src/log-server.ts` | low |

## 6. Discovery

| Section | Spec requires | Reference does | Where | Severity |
| --- | --- | --- | --- | --- |
| 6 | Discover policies through DNS and HTTPS | `StaticResolver` maps domains straight to server URLs for tests and demos; it must not be used in production | `packages/lib/src/resolver.ts` | low |

## 7. Requests and admission

| Section | Spec requires | Reference does | Where | Severity |
| --- | --- | --- | --- | --- |
| 7.2 | The recipient's home server refuses (413) a request whose copies exceed the sealed size of an 8192-byte request | Only the sender checks; the server accepts any body up to its 40 MiB limit | `packages/server/src/server.ts` (`deliverLocal`, `deliverAnonymous`) | medium |
| 7.7 | (comment accuracy) | `admission.ts` says "the server never learns who someone's contacts are"; the shared-contacts routes store them in the clear (Section 7.9) | `packages/lib/src/admission.ts` | low |

## 8. Threads and messages

| Section | Spec requires | Reference does | Where | Severity |
| --- | --- | --- | --- | --- |
| 8.11 | Expire blobs | Blobs never expire | `packages/server/src/store.ts` | low |
| 8 | (comment accuracy) | The `MessageBody.audience` comment says humans-only messages go outside MLS; they go in a humans-only MLS thread (Section 11.4) | `packages/lib/src/message.ts` | low |
| 8 | (no protocol rule) | The MLS key store is one serialized blob per client, so one client can't run in two processes at once | `packages/lib/src/mls.ts`, `packages/mls` | low |

## 10. Delivery and metadata protection

| Section | Spec requires | Reference does | Where | Severity |
| --- | --- | --- | --- | --- |
| 10.5.1 | `token_key_id` as in RFC 9578, over the `id-RSASSA-PSS` SubjectPublicKeyInfo | Hashes the plain `rsaEncryption` SubjectPublicKeyInfo, so tokens don't interoperate with other Privacy Pass implementations | `packages/lib/src/privacypass.ts` (`tokenKeyId`) | medium |
| 10.7, 15 | Delete mailbox items once read, expire parked items, keep counters only for their window | Mailbox items, parked items and counters live in memory until restart | `packages/server/src/store.ts` | low |
| 10.6 | (documentation accuracy) | The server README says retries last "about five days"; the schedule totals about 4.4 days | `packages/server/README.md`, `packages/server/src/server.ts` | low |

## 12. Live sessions and handoff

| Section | Spec requires | Reference does | Where | Severity |
| --- | --- | --- | --- | --- |
| 12.5 | A guest doesn't join a non-HTTPS `url` outside local testing | Any URL scheme is accepted | `packages/lib/src/client.ts` (`joinLiveSession`), `packages/lib/src/live.ts` | medium |

## 13. Interoperability with email

| Section | Spec requires | Reference does | Where | Severity |
| --- | --- | --- | --- | --- |
| 13.8 | Apply the recipient domain's MTA-STS policy when sending directly; use DANE where available | Sends to the lowest-preference MX with opportunistic TLS only | `packages/server/src/smtp.ts` | medium |
| 13.4 | Read the message's author correctly | The client takes only the first From address and ignores Sender | `packages/lib/src/client.ts` (`onLegacy`), `packages/lib/src/legacy.ts` | low |

## 6.8 Multi-home domains

| Section | Spec requires | Reference does | Where | Severity |
| --- | --- | --- | --- | --- |
| 6.8.6 | (no protocol rule; Section 6.8.10 lists it as open) | The log is never compacted and a restart replays all of it; membership is fixed at start | `packages/server/src/cluster.ts`, `packages/server/src/raft.ts` | medium |
| 6.8.4 | A home ignores a delivery whose id is already in the recipient's mailbox | Repeated deliveries after an ambiguous failure are stored again | `packages/server/src/server.ts` (`deliverLocal`) | medium |
| 6.3, 10.4 | Callers find a working home | The OHTTP relay and the policy's `ohttp.gateway` name only the first home, so sealed deliveries through a relay don't fail over | `packages/server/src/relay-server.ts`, `packages/server/src/server.ts` (`policy`) | medium |
| 6.8.5 | Everything a request changes is committed before it is answered | `SignetServer.setClaims` changes the store without waiting for the commit; a failover just after it can lose the claim | `packages/server/src/server.ts` | low |
| 6.8.5 | (no protocol rule) | Replicas apply batches with their own clock, so `receivedAt` and the expiry of parked deliveries differ by the replication delay | `packages/server/src/cluster.ts` | low |
| 6.8.6 | Cluster calls are signed as server requests (Section 4.6) | They are checked for the domain key and a fresh timestamp but not for a repeated nonce; Raft tolerates a replayed call | `packages/server/src/cluster.ts` (`handle`) | low |
| 6.8.6 | (no protocol rule) | No pre-vote: a replica cut off from the others raises its term and forces an election when it returns | `packages/server/src/raft.ts` | low |
| 6.8 | A deployment can run a cluster | No command-line or environment configuration for `signet server`; clusters are built in code (`SignetServer` with `cluster`, `ClusterWitness`), and an operator copies the domain, VRF, gateway and intake keys to each replica | `packages/server/src/main.ts` | medium |

## 6.9 Multi-operator domains

| Section | Spec requires | Reference does | Where | Severity |
| --- | --- | --- | --- | --- |
| 6.9.4 | A home reaches the owner's registrar over some channel | `LocalRegistrar` runs in the home's own process, so a home that isn't run by the domain owner can't bind addresses; there is no network registrar | `packages/server/src/registrar.ts` | high |
| 6.9.4 | Claims and legacy attestation go through the registrar | A home without the domain key answers 501 for organisation claims and for legacy-mail attestation | `packages/server/src/server.ts` | medium |
| 6.9.6 | A client repeats a registration with a home that was down | Key packages are topped up at every sync, but delivery tokens, contacts and view grants a down home missed are not repeated | `packages/lib/src/client.ts` | medium |
| 6.9.6 | A client compares what its homes return and flags one that is missing items | Not done; the spec doesn't define the comparison | `packages/lib/src/client.ts` | medium |
| 6.9.2 | A client refuses a lower `seq` than any it has held | The highest `seq` is kept in the resolver's memory only, so a restarted client forgets it | `packages/lib/src/resolver.ts` | medium |
| 6.9.7 | (open issue) | Sealed deliveries to homes after the first go direct, not through OHTTP | `packages/server/src/server.ts` (`relayOnce`) | medium |
| 6.9.7 | (open issue) | Each home accepts a Privacy Pass token once, so one token can be spent at each home | `packages/server/src/server.ts` (`deliverAnonymous`) | low |
| 6.9.5 | A client resends through another home when its own can't be reached | Done for any failure of the call. A home that accepts and then drops the message isn't noticed | `packages/lib/src/client.ts` (`call`) | medium |
| 6.9 | A deployment can run a multi-operator domain | There is no command-line or environment configuration for operator mode; it is built in code, and the owner signs the statement with `signOperators` | `packages/server/src/main.ts` | medium |
| 6.9.7 | (open issue) | The VRF key, and the intake key with an intake, are given to every home | `packages/server/src/server.ts` | medium |

