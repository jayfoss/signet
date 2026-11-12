import { existsSync } from 'node:fs';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type {
  AdmissionDecision,
  ClientKeys,
  ClientSnapshot,
  KeyPair,
  LogEntry,
  SignedMessage,
  SignedRequest,
  TrustedLog,
} from '@signet/lib';
import { Identity } from '@signet/lib';

export interface Config {
  address: string;
  trustedLogs: TrustedLog[];
  /** Domain to server URL, instead of DNS. For local setups. */
  servers?: Record<string, string>;
  /** OHTTP relay for anonymous directory lookups (cross-checks and `monitor`). Without one they go direct. */
  ohttpRelay?: string;
}

export interface PendingRequest {
  receivedAt: string;
  request: SignedRequest;
  admission: AdmissionDecision;
}

export interface StoredMessage {
  thread: string;
  message: SignedMessage;
  sender: { clientId: string; kind: string; label?: string };
}

type SavedIdentity = { principal: string; key: KeyPair; entries: LogEntry[] };

/**
 * One client's private directory. Keys and history stay on this device; files are written owner-only.
 * Only the primary device holds identity.json, the key that approves and revokes clients.
 */
export class Home {
  constructor(readonly dir: string) {}

  static async create(dir: string): Promise<Home> {
    await mkdir(dir, { recursive: true, mode: 0o700 });
    return new Home(dir);
  }

  exists(name: string): boolean {
    return existsSync(join(this.dir, name));
  }

  async read<T>(name: string): Promise<T | undefined> {
    if (!this.exists(name)) return undefined;
    return JSON.parse(await readFile(join(this.dir, name), 'utf8')) as T;
  }

  async need<T>(name: string, hint: string): Promise<T> {
    const value = await this.read<T>(name);
    if (value === undefined) throw new Error(`${join(this.dir, name)} is missing: ${hint}`);
    return value;
  }

  /** Write via a temp file and rename, so a crash never leaves half a key file behind. */
  async write(name: string, value: unknown): Promise<void> {
    const path = join(this.dir, name);
    await writeFile(`${path}.tmp`, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
    await rename(`${path}.tmp`, path);
  }

  config(): Promise<Config> {
    return this.need('config.json', 'run `signet init` first');
  }

  keys(): Promise<ClientKeys> {
    return this.need('client.json', 'run `signet init` or `signet add-client` first');
  }

  async identity(): Promise<Identity> {
    const saved = await this.need<SavedIdentity>('identity.json', 'only the primary device can approve or revoke clients');
    return Identity.restore(saved);
  }

  saveIdentity(identity: Identity): Promise<void> {
    return this.write('identity.json', identity.export());
  }

  snapshot(): Promise<ClientSnapshot | undefined> {
    return this.read('snapshot.json');
  }

  async requests(): Promise<PendingRequest[]> {
    return (await this.read<PendingRequest[]>('requests.json')) ?? [];
  }

  async messages(): Promise<StoredMessage[]> {
    return (await this.read<StoredMessage[]>('messages.json')) ?? [];
  }
}
