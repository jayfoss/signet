# @signet/lib

Protocol code for Signet, shared by the server and client apps. Spec: [Signet Protocol, Version 0](../../docs/signet-protocol-v0.txt)

| File | What it holds |
| --- | --- |
| `identity.ts` | `Identity` (the key that signs the account's log), `replayLog`, client certificates, scopes, key rotation and recovery |
| `directory.ts` | Domain policy, domain binding, directory entries, `IdentityChangedError` |
| `cards.ts` | The public card, the contact view and per-contact grants: what strangers, contacts and counterparties see |
| `vrf.ts` | Transparency-log indexes as RFC 9381 VRF outputs (ECVRF-EDWARDS25519-SHA512-TAI, in the native core) |
| `transparency.ts` | RFC 9162 Merkle tree: inclusion and consistency proofs, signed tree heads, `MerkleLog` |
| `crypto.ts` | Ed25519, AES-256-GCM, and HPKE (RFC 9180, via `@hpke/core`) for one-shot sealing |
| `mls.ts` | Threads as MLS groups (RFC 9420) through the OpenMLS core in `packages/mls`; leaves are certified client keys |
| `sealed.ts` | Sealed-sender delivery tokens derived from the MLS exporter |
| `ohttp.ts`, `bhttp.ts` | Oblivious HTTP (RFC 9458) encapsulation, with Binary HTTP (RFC 9292) as the inner message |
| `privacypass.ts` | Privacy Pass tokens (RFC 9577/9578 type 2) on RSA blind signatures (RFC 9474) |
| `request.ts` | Request envelope (HPKE-sealed per admitting client, 8 KB cap) and introductions |
| `admission.ts` | Contacts, own organisation, trusted domains and introductions decide who skips the queue |
| `intents.ts` | Core intent schemas (scheduling, files, status, `pay.request`/`pay.sent`, handoff, live sessions), reverse-DNS extensions, agent scopes and `commit_usd` limits |
| `message.ts` | Signed message bodies carried inside MLS application messages |
| `attachments.ts` | Files encrypted under per-file keys; the key travels in the message |
| `legacy.ts` | The `Signet:` header for plain email, and inbound mail sealed to clients on arrival |
| `resolver.ts` | `_signet` TXT discovery (with `host=` delegation, MTA-STS style) + `.well-known` policy, no redirects, cached for `max_age` against downgrades |
| `gmail.ts` | Gmail mode: send through the Gmail API with an attested header, scan new mail for Signet headers |
| `client.ts` | `SignetClient`: lookup, requests, threads, rekey, attachments, plain email, sync, monitor, snapshots. It talks only to its own home server |

## How the pieces check each other

- A directory entry is accepted only if the domain key signed the binding, the identity key signed the card (and view), the VRF proof gives the address's log index, and the log's latest leaf at that index commits to that identity key, card and view, under a signed tree head consistent with the last one this client saw.
- An MLS welcome is joined, and a commit applied, only after every member's credential matches an active client in its owner's log (the core reports them first; see `packages/mls`). Revoking a client in the log is what removes it from threads (`rekey`).
- Clients pin each address's identity key. A key the card's key chain leads to from the pinned one is accepted, with a `key-changed` event. Any other key, or a not-enrolled answer the log can't back up, raises `IdentityChangedError`.

## Enrolling a client

A new client makes its own keys; only the public halves travel. It sends an enrollment request (`requestEnrollment`): its keys, kind, label, the scopes and limits it asks for, and a nonce, signed with its new key. The identity holder shows the request and a 16-character fingerprint, chooses the scopes and limits itself, and certifies it (`identity.approveClient`). Two ways to carry the request:

- **Link or QR code** (`enrollmentLink`; `signet enroll-request`, `approve`, `enroll-finish`): for a new device beside you, or a service that hands you a link. The new client then fetches its certificate (`fetchApprovedCert`).
- **Pairing code** like `4821-H7KQ-9XRM` (`client.openPairing`, `pairAsOwner`, `joinPairing`; `signet pair` and `join`): for a client somewhere else. The digits name a relay slot on the home server; both sides run SPAKE2 over the letters and seal the request and the reply under the key it gives. The server relays without learning the code, so it can't swap the keys, and a slot holds one attempt.

`Identity.enrollClient` (keys made beside the identity key) is for tests and demos only.

## Identity keys: rotation and recovery

- **Rotation** (`identity.rotateKey()`, `signet rotate`) appends a `key-change` entry signed by the old key that names the new one. Later entries are signed by the new key. Clients, threads and grants carry on.
- **Recovery key** (`identity.setRecovery()`, `signet recovery-key --out FILE`): the identity key names a recovery key, kept offline. Signet keeps only its public half.
- **Recovery** (`Identity.recover`, `signet recover`): with every device and the identity key gone, the recovery key proves itself to the home server (`POST /v0/recovery/:user`), gets the log back and signs a `recover` entry naming a fresh identity key. The recovery key is then used up. Grants signed before a recovery stop counting, because whoever holds the old key may not be the owner.
- **What contacts see:** the public card carries the chain of key changes. Someone who pinned an older key follows the chain without trusting the domain, and gets `key-changed` with `how: 'rotated'` or `'recovered'`; a recovery is worth a word with the person. A domain rebinding to a key off the chain is still `IdentityChangedError`.
- **Limits:** an attacker who steals the identity key can rotate it or replace the recovery key, like the owner. Monitoring (`signet monitor`) shows every key the log ever bound.

## What others can see

- **Public card (anyone):** the identity key, unlabeled request keys, and the intake agent if there is one, with the intents it handles for strangers. With an exclusive intake, requests are sealed to the intake alone.
- **Contact view (people you admitted):** each client's keys and whether it is a device or an agent. No labels, no scopes. Owners release it per contact (`/v0/contacts/grant`), and a sender presents its own view inside a request.
- **Private log (owner and its home server):** labels, scopes and limits. Labels reach a thread only if a client chooses to share them (`shareLabel`).
- **Grants:** an agent's authority beyond its intake listing is a grant signed by the identity key for one counterparty, presented only to that counterparty. Revoked grant ids appear in the contact view.
- **Unlisted addresses (opt-in, two levels):** a domain that runs an intake publishes its key in the policy. Each user then chooses `identity.setUnlisted(true)` (`signet unlisted on`). Strangers get the same domain-signed `unlisted` answer for that address as for one that doesn't exist, with no VRF proof, so neither the directory nor the log tells them apart. Their requests are sealed to the intake key; the home server opens each one, re-seals it to the user's own request keys (devices only, for humans-only), and drops it if there's no such user, giving the sender the same answer either way. The cost: the domain can read first-contact requests to unlisted users. Once the user accepts, its view is released to the sender, who verifies it against the log as usual, and the thread is end to end. Contacts and colleagues see the address as before. A domain could also claim a listed user is unlisted to read their first requests; it could already withhold them.
- **Keeping a domain honest about who is unlisted:** a domain with an intake could tell strangers a *listed* user is unlisted, to read first requests. Three checks narrow that down:
    - A sender that gets "unlisted" from its server asks again anonymously, through the OHTTP relay. If that answer shows the person, it sends straight to their keys and raises a `directory-alert`.
    - The owner's `monitor` makes the same anonymous lookup and alerts if strangers are shown something other than the truth: unlisted while listed, listed while unlisted, or a different card. The domain can't tell the owner's check from a sender's.
    - A sender that already knows the address (a pinned key, or plain email with an authenticated `Signet:` header) refuses the intake with `HiddenAddressError`.
    
    Contact cards (`client.contactCard()`, `importContactCard`; `signet card`, `import-card`) carry the person's own domain binding, signed card and VRF proof. Checked against the log, they let the holder reach the person's keys directly even when the person is unlisted.
- **Transparency log:** leaves sit at VRF indexes, so the log can't be used to test guessed addresses. Directory lookups are the only way to learn an index, and they are rate-limited; misses cost ten times as much, and a domain whose lookups mostly miss is cut off for the day.

## Humans-only mail

Senders can mark a request, a thread message or a plain email humans-only (password resets, sign-in codes), to keep it away from the recipient's agents. **The sender only asks; the recipient decides.**

- By default the request is honoured cryptographically. A humans-only request is sealed only to the recipient's human devices (the card's `humanKeys`). In a conversation, humans-only messages go to a **humans-only thread**: an MLS group of the same people whose members are only devices and opted-in agents (the view's `humansOnly` members). `send(thread, { humansOnly: true })` opens it beside the ordinary thread on first use, and clients link the two. Accepting a humans-only request starts one. Clients refuse welcomes and commits that would put a non-opted-in agent in such a thread, and `rekey` keeps the membership in line with each owner's policy.
- The recipient can opt agents in with a signed `set-audience-policy` entry (`identity.setAudiencePolicy([...])`, `signet audience --agents ...`). Opted-in agents get those keys too, so an over-cautious sender can't keep someone's own assistant out against their wishes.
- **Escrow gets everything.** An `org-escrow` client receives every request, every humans-only thread and all humans-only mail, regardless of the sender's flag or the owner's policy. It must hold `read:*`, and contacts see it as `escrow` in the contact view.
- Plain email carries `Signet-Audience: humans`. A Signet server receiving it seals it only to the readers the recipient's policy allows. In Gmail mode, where nothing can be sealed, the client applies the same policy when scanning.
- It can't stop the recipient themselves from showing a message to an agent, and isn't meant to.

## Asking a colleague's agent (disclosure)

When an agent needs something a colleague holds, `requestInfo` sends an `info.request`: the question, the purpose, and claims the organisation signed about the asker with its domain key (`ownClaims`, set by the admin with `server.setClaims`). The answering agent gets `disclosureContext`: the verified requester and the kind of client that asked, the claims that check out, and the exact audience, meaning every client that would read an answer, with its hash. Its owner's rules decide:

- **Answer** (`answerInfo`) or **refuse** (`refuseInfo`). An answer carries `approvedFor`, the audience hash it was decided for.
- **Escalate** (`escalateInfo`): an approval card with the draft and the audience goes to a thread of the owner's own clients only. On a device, `approvalCard` reads it and `decideApproval` releases it in one of three ways:
    - to the thread;
    - to the requester only, through the humans-only sibling, so their devices get it and their agents don't;
    - as a narrower answer.
  
  Or it refuses. Release to the thread is refused if the membership has changed since the card was drawn, so an approval covers the people the owner saw, not whoever is there now. Only devices can decide.

`info.request` and `info.answer` need the sender's `intent:info.*` scope but no grant, since asking and answering commit nobody. Demo: `pnpm disclosure-demo`.

## Live sessions and handoff

A thread can move to a live A2A session (Agent2Agent JSON-RPC) when two agents need fast back-and-forth.

- **The offer is a `session.offer` intent in the thread** (`offerLiveSession(thread, card)`), so only members see the gateway URL. It names a session id, an expiry and the hash of the host's A2A agent card. The guest fetches the card, checks the hash and connects (`joinLiveSession`).
- **The bearer token is never sent.** Both sides derive it from the thread's MLS exporter for the current epoch (`liveToken`), and the host's `LiveGateway` checks it with `authorizeLive`. Only current members can compute it, and a rekey (say, after revoking an agent) changes it, so old sessions stop working. `endLiveSession` ends a session explicitly with `session.end`.
- **Nothing binding happens live.** Commitments come back to the thread as signed messages and intents, where grants and scopes apply. That's why receivers accept `session.*` from any agent in the thread, as they do `handoff.human`; the sender still needs `intent:session.*` to offer one.
- **`handoff.human`** marks the thread as needing its owner. The owner's devices get a `handoff` event, live sessions on the thread end, and the owner's agents can't send in it until one of the owner's devices replies. The other side's agents aren't held.

## Spoofing

- **Signet traffic can't be spoofed.** Every request and message is signed by a client key that appears in the sender's contact view. That view is signed by their identity key, which their domain binds and the transparency log records (and which senders pin). MLS also authenticates every thread message. There is no unauthenticated From line to forge.
- **Plain email is still plain email.** A `Signet:` header is only a hint, because nothing in SMTP protects it. The sender's home server signs it with the domain key over the From, To and Subject, plus a timestamp and nonce (`attestedSignetHeader`). Recipients report `onSignet` (the address is enrolled with that key) separately from `authenticated` (its domain vouched for *this* email). A pasted fingerprint, or a real header replayed on another subject, is `onSignet` but not `authenticated`. SPF, DKIM and DMARC still decide plain mail's tier.
- **Lookalike domains** (`acrne.com`) are the remaining trick: Signet stops anyone sending *as* a domain, not registering a similar one. Clients flag requests and mail from domains that read like ones you know, and never let them into the inbox tier.

## Metadata

- **Lookups, key-package claims and log queries go through the client's own home server.** That server signs as its domain and passes a hash of the requesting user, so remote servers and the log can rate-limit per requester without seeing client IPs or addresses.
- **Thread traffic is sealed.** Messages, commits and welcomes carry no sender address or client id. The recipient's server accepts them on a per-epoch delivery token (an MLS exporter secret registered as a hash) and parks deliveries whose token isn't registered yet. Welcomes name joiners only by hashed client id.
- **First-contact requests are anonymous** when the recipient's domain accepts Privacy Pass. The envelope carries a token instead of a sender, and the sender is named only inside the copies sealed to the recipient's clients. The sender's home server attests and rate-limits its user; a separate issuer signs blinded tokens it can't link; the recipient's server checks the token is valid, unspent and bound to its domain.
- **Sealed and anonymous deliveries travel through an Oblivious HTTP relay.** The receiving server sees only the relay's address. The relay sees which server is sending and to which domain, but not the content.
- **What still shows:** servers see thread-epoch linkage, timing and sizes (padded to 256 bytes). Relay and gateway must not collude, and the issuer must not collude with the recipient's server. Requests sent with `anonymous: false`, and welcomes to people who never sent a request, still carry the sender.

## Notes

- Where this code falls short of the spec, it's listed in [ERRATA.md](ERRATA.md).
- MLS needs the native addon: run `pnpm build:mls` once (Rust toolchain required).
- The transparency log is trusted for "latest leaf" answers, and one operator is not enough for production. Signet's own code hasn't been audited.

## Tests

Run one file at a time from this directory:

```bash
npx jest src/__tests__/messaging.test.ts -i
```
