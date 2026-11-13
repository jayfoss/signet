# @signet/server

Seven roles from one app, chosen with `SIGNET_ROLE`:

- **home** (default): one domain's server. It serves the policy and directory, writes every directory change to the transparency log, hands out MLS key packages, accepts mail from its own clients, relays to other domains, and holds mailboxes and blobs that are all ciphertext. With `SIGNET_SMTP_PORT` it also accepts plain email, checks SPF, DKIM and DMARC, and encrypts each message to the recipient's clients on arrival. Plain email out goes through `SIGNET_SMTP_RELAY` or straight to MX, optionally DKIM-signed.
- **log**: the transparency log service. Domains append leaves; anyone reads tree heads, latest leaves, history and consistency proofs.
- **issuer**: the Privacy Pass issuer. Home servers forward their users' blinded token requests, signed as their domain; it signs them without seeing the tokens and caps tokens per domain per day.
- **relay**: the Oblivious HTTP relay. It forwards encapsulated deliveries to the gateway a Signet domain publishes, and keeps nothing.
- **witness**: a replica that only keeps the replication log and votes, so two homes of one operator survive the loss of one (Section 6.8).
- **registrar**: the domain owner's service for the things only the domain key may do, when the domain's homes are run by other operators: binding addresses, releasing them and attesting plain email (Section 6.9.4).
- **sign-operators**: prints the owner's signed list of homes and exits.

A home can also run as one of several replicas (`SIGNET_CLUSTER_ID`) or as one operator's home of a multi-operator domain (`SIGNET_HOME_KEY`); the environment variables are listed at the top of `src/main.ts`.

Storage is in memory.

## Home server routes

| Route | Who calls it |
| --- | --- |
| `GET /.well-known/signet.json` | Anyone: the domain policy, including which log it writes to |
| `GET /v0/directory/:user` | Other Signet servers (domain-signed, per-domain and per-requester limits), or anyone within a small per-IP budget. Returns the public card and VRF proof; the contact view only if the owner released it to the requester. With an intake (`SIGNET_INTAKE=1`), unlisted and unknown addresses get the same signed `unlisted` answer, and requests sealed to the intake key are re-sealed to the user or dropped |
| `POST /v0/directory/:user/claim` | Other Signet servers only: one key package per requested client, then the reusable last-resort one |
| `POST /v0/log/:user` | Anyone: accepted only if it extends the stored log; a key change in it (signed by the old key or the recovery key) moves the domain binding to the new key |
| `POST /v0/recovery/:user` | Whoever proves the recovery key the log names (a fresh signed timestamp): returns the stored log to sign a recovery onto. Everyone else gets 404 |
| `GET /v0/lookup`, `POST /v0/claim`, `GET /v0/transparency/*` | The domain's own clients: proxied to other domains and the log, signed as this domain |
| `POST /v0/submit` | The domain's own clients (`send` scope). With a `token`, the delivery is sealed and leaves without a sender |
| `GET /v0/mailbox?after=n` | The domain's own clients |
| `POST /v0/contacts/grant` | The domain's own clients, releasing their contact view to hashed requesters |
| `POST /v0/delivery-tokens` | The domain's own clients, registering token hashes; releases deliveries parked for them |
| `GET /v0/keypackages/count`, `POST /v0/keypackages` | The domain's own clients, topping up one-time and last-resort key packages |
| `POST /v0/blobs`, `GET /v0/blobs/:id` | Encrypted attachments: own clients upload; anyone with the capability URL downloads |
| `POST /v0/legacy/send` | The domain's own clients, for plain email to non-Signet recipients (the server attests its Signet header) |
| `POST /v0/legacy/attest` | The domain's own clients: a Signet header signed with the domain key for this From, To and Subject (Gmail mode) |
| `POST /v0/deliver` | Other Signet servers, signed by their domain key (requests and first-contact welcomes) |
| `POST /v0/deliver-sealed` | Anyone holding a registered delivery token; unknown tokens are parked for 24 hours, at most 500 per user |
| `POST /v0/deliver-anonymous` | Anyone with a valid, unspent Privacy Pass token bound to this domain, for one request |
| `GET /.well-known/ohttp-gateway`, `POST /v0/ohttp` | The OHTTP key configuration and gateway; the gateway only runs the two delivery routes above |
| `GET /v0/issuer`, `POST /v0/tokens` | The domain's own clients: the issuer's public key, and attested blinded token requests (per-user daily cap) |
| `POST /v0/pairing`, `POST /v0/pairing/:slot/a` | The domain's own devices: open a ten-minute relay slot for pairing a new client, and post the owner's two messages |
| `POST /v0/pairing/:slot/b`, `GET /v0/pairing/:slot/:side` | The new client, which has no account yet (per-IP daily limit): its two messages, and reading the other side's. A slot holds two messages a side, so a wrong code burns it |
| `POST /v0/enroll` | Only with `SIGNET_OPEN_ENROLLMENT=1` (demo) |

Relays that fail are retried with backoff (about 4.4 days by default), then bounced to the sender's mailbox. Daily limits (`DEFAULT_LIMITS` in `src/server.ts`) cap requests per sender and sender domain, lookups per requester, domain and anonymous IP, and key-package claims per requester and client. A lookup that finds nobody counts ten times, and a domain whose lookups mostly miss (after 50 in a day) is refused for the rest of the day. Colleagues on the same domain see each other's contact views unless `colleaguesSeeViews` is off.

## Running alongside Google Workspace (or any existing mail)

Signet doesn't need the domain's MX. Keep Google for all plain email and run the home server with SMTP off:

| Record | Value |
| --- | --- |
| MX, SPF, `google._domainkey`, `_dmarc`, `_mta-sts` | unchanged (Google) |
| `_signet.example.com` TXT | `v=signet0; host=signet.example.com` |
| `signet.example.com` | the Signet home server (a CNAME to a hosted one is fine) |

The `host` must be the domain or a subdomain of it, and the policy at `https://<host>/.well-known/signet.json` is fetched without following redirects. Clients send plain email through Gmail (`signet mail ADDRESS --via gmail`), with headers attested by `POST /v0/legacy/attest`. See `signet-gmail-coexistence.md` in the main checkout for the research behind this, including the Gmail API scope requirements.

## Log routes

`GET /v0/tree-head` and `GET /v0/consistency?first=&second=` are public. `GET /v0/latest?key=` and `GET /v0/history?key=` need a domain signature (with per-domain and per-requester limits) or fall within a small per-IP budget, so the log can't be used to test who is enrolled. `POST /v0/append` is domain-signed.

## Demo

Three domains, a log and an SMTP sink on localhost: an introduced request, an MLS thread with an attachment, a revocation, plain email both ways, and two rebinding attacks.

```bash
pnpm demo
```

The disclosure demo: Jerzy's agent asks his colleague Mia's agent for a fact he may not be cleared for. Her agent asks Mia on her phone, showing who would read the answer. She releases it to Jerzy's phone only, and her phone refuses a second release after someone joins the thread.

```bash
pnpm disclosure-demo
```

## Run

```bash
SIGNET_ROLE=log SIGNET_DATA_DIR=./data/log PORT=4200 pnpm server
SIGNET_DOMAIN=example.org SIGNET_DATA_DIR=./data/home SIGNET_LOG='{"url":"http://localhost:4200","key":"<log key>"}' PORT=4100 pnpm server
```

`SIGNET_DATA_DIR` keeps everything that must survive a restart. Each role's own key goes there. The home server keeps `signet.db`, an SQLite database (Node's built-in `node:sqlite`, WAL mode, full fsync, one transaction per change) holding accounts, mailboxes, key packages, tokens, spent Privacy Pass nonces, replay caches, claims, its VRF, gateway and intake keys, and deliveries waiting to be retried, which resume after a restart. The log appends leaves to `leaves.jsonl`, and the issuer keeps its RSA key. Without it everything is in memory and the keys are thrown away. One home server process per domain; running several behind a load balancer would want the same schema (`src/store.ts`) in a networked database. See `src/main.ts` for every environment variable.

## Still to do

The gaps between this code and the spec, with severities, are in [`packages/lib/ERRATA.md`](../lib/ERRATA.md); the high-severity ones come first. Beyond those: a hosted A2A gateway for agents without their own endpoint, several home server processes per domain, delegation chains for sub-agents, a second log operator, more than one relay and issuer operator, and padding and batching against timing analysis.
