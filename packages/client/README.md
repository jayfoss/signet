# @signet/client

A command-line Signet client. Each client, whether a person's device or an agent, has its own directory (`SIGNET_HOME`, default `~/.signet`) holding its keys, MLS state, pinned identities and message history, written owner-only. Only the primary device's directory holds `identity.json`, the key that approves and revokes clients.

```bash
pnpm cli init --address you@example.org --log-url=URL --log-key=KEY
pnpm cli lookup jerzy@acme.com
pnpm cli request jerzy@acme.com --subject "Intro" --intent schedule.propose --args '{"durationMin":30}'
pnpm cli sync
```

Run `signet --help` for every command. Highlights:

- `add-client --kind agent --label Clerk --scopes read:*,send,admit,intent:schedule.* --out ~/.signet-clerk --intake 'schedule.*'` approves an agent, makes it the public intake for scheduling, and writes its own client directory; run it with `SIGNET_HOME=~/.signet-clerk`. Add `--intake-only` to seal all first contact to it.
- `grant ~/.signet-clerk alice@example.org --intents 'schedule.*,com.example.quote.*' --limit-usd 100` gives that agent authority with one contact; only Alice ever sees the grant.
- `revoke CLIENT_ID`, then `rekey THREAD`, removes a client from its threads with an MLS commit.
- `mail ADDRESS` goes over Signet when the address is enrolled and by plain email otherwise.
- `monitor` checks your address's history in the transparency log and reports anything this device can't account for.

**Humans-only:** `--humans-only` on `request`, `send` and `mail` asks that the recipient's agents not read it; on `send` it goes to the thread's humans-only sibling, opened on first use. `audience --agents ID,...` (primary device) decides which of *your* agents may read such mail anyway.

**Gmail mode**, for domains whose mail stays on Google: set `SIGNET_GMAIL_TOKEN` to an OAuth access token (`gmail.send` to send, `gmail.metadata` to scan; the latter is a restricted scope). Then `signet mail ADDRESS --via gmail` sends plain email through the Gmail API with an attested Signet header, and `signet gmail-scan` reports new mail carrying Signet headers, saying whether each was authenticated by the sender's domain.

For local setups without DNS, pass `--servers '{"example.org":"http://localhost:4100"}'` to `init`.
