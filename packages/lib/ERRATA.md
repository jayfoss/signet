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
