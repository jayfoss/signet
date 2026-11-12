/* eslint-disable no-console */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { KeyPair, Resolver, TrustedLog } from '@signet/lib';
import { DnsResolver, StaticResolver, exportIssuerKey, generateIssuerKey, generateSigningKey, importIssuerKey } from '@signet/lib';
import { IssuerServer } from './issuer-server';
import { TransparencyLogServer } from './log-server';
import { RelayServer } from './relay-server';
import { SignetServer } from './server';
import { InboundSmtp, OutboundSmtp } from './smtp';

/**
 * SIGNET_ROLE            "home" (default), "log", "issuer" (Privacy Pass) or "relay" (Oblivious HTTP)
 * SIGNET_KEY             JSON {"publicKey","privateKey"}: the domain key, or the log key. Unset: kept in SIGNET_DATA_DIR
 * SIGNET_DATA_DIR        folder for everything that must survive a restart: accounts and mailboxes (home), leaves
 *                        (log), the issuer key, and each role's own key. Unset: in memory, with a throwaway key
 * SIGNET_PUBLIC_URL      URL published in the policy (defaults to the listen address)
 * SIGNET_STATIC_SERVERS  JSON {"domain": "url"} to skip DNS, e.g. for local testing
 * PORT                   HTTP port (4100)
 *
 * Home servers also read:
 * SIGNET_DOMAIN          domain this server answers for (required)
 * SIGNET_LOG             JSON {"url","key"} of the transparency log (required)
 * SIGNET_OPEN_ENROLLMENT "1" lets anyone enroll over HTTP (demo only)
 * SIGNET_INTAKE        "1" runs a domain intake, so users can choose to be unlisted
 * SIGNET_SMTP_PORT       port for inbound plain email (off if unset)
 * SIGNET_SMTP_TLS_KEY / SIGNET_SMTP_TLS_CERT  files for STARTTLS
 * SIGNET_SMTP_RELAY      JSON {"host","port","secure","auth"} for outbound plain email (direct to MX if unset)
 * SIGNET_DKIM            JSON {"selector","privateKey"} to DKIM-sign outbound plain email
 * SIGNET_ISSUER          JSON {"url","key":{"name","publicKey"}} of the Privacy Pass issuer (anonymous requests)
 * SIGNET_OHTTP_RELAY     URL of the Oblivious HTTP relay for sealed and anonymous deliveries
 *
 * Issuers read SIGNET_ISSUER_NAME. Their RSA key is kept in SIGNET_DATA_DIR.
 */
const env = (name: string): string | undefined => process.env[name] || undefined;
const jsonEnv = <T>(name: string): T | undefined => {
  const value = env(name);
  return value ? (JSON.parse(value) as T) : undefined;
};

const dataDir = (): string | undefined => {
  const dir = env('SIGNET_DATA_DIR');
  if (dir) mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
};

/** A JSON file in the data folder, created by `make` on first start and read on every start after. */
function kept<T>(name: string, make: () => T, save: (value: T) => unknown = (value) => value, load: (saved: never) => T = (saved) => saved): T | undefined {
  const dir = dataDir();
  if (!dir) return undefined;
  const file = join(dir, name);
  if (existsSync(file)) return load(JSON.parse(readFileSync(file, 'utf8')) as never);
  const value = make();
  writeFileSync(file, JSON.stringify(save(value)), { mode: 0o600 });
  return value;
}

function key(): KeyPair {
  const configured = jsonEnv<KeyPair>('SIGNET_KEY') ?? kept('key.json', generateSigningKey);
  if (configured) return configured;
  console.warn('SIGNET_KEY and SIGNET_DATA_DIR are unset; using a throwaway key, and nothing survives a restart');
  return generateSigningKey();
}

function resolver(): Resolver {
  const servers = jsonEnv<Record<string, string>>('SIGNET_STATIC_SERVERS');
  return servers ? new StaticResolver(new Map(Object.entries(servers))) : new DnsResolver();
}

async function main(): Promise<void> {
  const port = Number(env('PORT') ?? 4100);
  if (env('SIGNET_ROLE') === 'log') {
    const dir = dataDir();
    const log = new TransparencyLogServer(key(), resolver(), undefined, dir ? join(dir, 'leaves.jsonl') : undefined);
    const url = await log.listen(port, '0.0.0.0', env('SIGNET_PUBLIC_URL'));
    console.log(`signet transparency log at ${url}, key ${log.publicKey}`);
    return;
  }

  if (env('SIGNET_ROLE') === 'issuer') {
    const name = env('SIGNET_ISSUER_NAME') ?? 'issuer.signet';
    const issuerKey = kept('issuer-key.json', () => generateIssuerKey(name), exportIssuerKey, importIssuerKey);
    const issuer = new IssuerServer(name, resolver(), undefined, issuerKey);
    const url = await issuer.listen(port, '0.0.0.0', env('SIGNET_PUBLIC_URL'));
    console.log(`signet Privacy Pass issuer at ${url}: ${JSON.stringify(issuer.publicKey)}`);
    return;
  }
  if (env('SIGNET_ROLE') === 'relay') {
    const relay = new RelayServer(resolver());
    console.log(`signet OHTTP relay at ${await relay.listen(port, '0.0.0.0', env('SIGNET_PUBLIC_URL'))}`);
    return;
  }

  const domain = env('SIGNET_DOMAIN');
  const log = jsonEnv<TrustedLog>('SIGNET_LOG');
  if (!domain || !log) throw new Error('SIGNET_DOMAIN and SIGNET_LOG are required');
  const server = new SignetServer({
    domain,
    domainKey: key(),
    resolver: resolver(),
    log,
    publicUrl: env('SIGNET_PUBLIC_URL'),
    openEnrollment: env('SIGNET_OPEN_ENROLLMENT') === '1',
    dataDir: dataDir(),
    intake: env('SIGNET_INTAKE') === '1',
    outbound: new OutboundSmtp(domain, { relay: jsonEnv('SIGNET_SMTP_RELAY'), dkim: jsonEnv('SIGNET_DKIM') }),
    issuer: jsonEnv('SIGNET_ISSUER'),
    ohttpRelay: env('SIGNET_OHTTP_RELAY'),
  });
  const url = await server.listen(port, '0.0.0.0');
  console.log(`signet home server for ${domain} at ${url}`);

  const smtpPort = env('SIGNET_SMTP_PORT');
  if (smtpPort) {
    const tlsKey = env('SIGNET_SMTP_TLS_KEY');
    const tlsCert = env('SIGNET_SMTP_TLS_CERT');
    const smtp = new InboundSmtp(server, tlsKey && tlsCert ? { tls: { key: readFileSync(tlsKey), cert: readFileSync(tlsCert) } } : {});
    console.log(`accepting plain email for ${domain} on port ${await smtp.listen(Number(smtpPort), '0.0.0.0')}`);
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
