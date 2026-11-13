import type { KeyPair, KeyRotation, LogLeaf, TrustedLog } from '@signet/lib';
import { domainAuthHeaders, domainKeyIndex } from '@signet/lib';

/**
 * Records a domain's key in its transparency log (Section 5.3.1) so a client meeting the domain for the first
 * time can check the key in the policy against it (Section 6.5). It asks the log first, and appends only if
 * the log does not already hold this key. Once it has succeeded it does nothing more.
 */
export class DomainKeyLogger {
  private done = false;
  private running?: Promise<void>;

  constructor(
    private readonly options: { domain: string; domainKey: KeyPair; log: TrustedLog; rotation?: KeyRotation; fetchImpl?: typeof fetch },
  ) {}

  ensure(): Promise<void> {
    if (this.done) return Promise.resolve();
    this.running ??= this.run().then(
      () => {
        this.done = true;
      },
      (error) => {
        this.running = undefined;
        throw error;
      },
    );
    return this.running;
  }

  private async run(): Promise<void> {
    const { domain, domainKey, log, rotation } = this.options;
    const fetchImpl = this.options.fetchImpl ?? fetch;
    const index = domainKeyIndex(domain);
    const query = `/v0/latest?key=${encodeURIComponent(index)}&domain=${encodeURIComponent(domain)}`;
    const answer = await fetchImpl(`${log.url}${query}`, { headers: domainAuthHeaders(domain, domainKey, 'GET', query, '') });
    if (answer.ok) {
      const { leaf } = (await answer.json()) as { leaf: LogLeaf | null };
      if (leaf?.kind === 'domain-key' && leaf.domainKey === domainKey.publicKey) return;
    }
    const leaf: LogLeaf = {
      v: 0,
      index,
      domain,
      kind: 'domain-key',
      identityKey: null,
      cardHash: null,
      viewHash: null,
      domainKey: domainKey.publicKey,
      ...(rotation ? { rotation } : {}),
      ts: new Date().toISOString(),
    };
    const body = JSON.stringify(leaf);
    const response = await fetchImpl(`${log.url}/v0/append`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...domainAuthHeaders(domain, domainKey, 'POST', '/v0/append', body) },
      body,
    });
    if (!response.ok) throw new Error(`the log refused the domain key: ${response.status} ${await response.text()}`);
  }
}
