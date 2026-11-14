import type { DirectoryEntry } from '@signet/lib';
import { Identity, requesterHash } from '@signet/lib';
import { Testbed } from '../testbed';

async function world() {
  const bed = await Testbed.start(['alpha.test', 'beta.test']);
  const alice = Identity.create('alice@alpha.test');
  const bob = Identity.create('bob@beta.test');
  const device = (identity: Identity) => bed.client(identity.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] }));
  const alicePhone = device(alice);
  const bobPhone = device(bob);
  await bed.publish(alice);
  await bed.publish(bob);
  await alicePhone.ready();
  await bobPhone.ready();
  return { bed, alicePhone, bobPhone };
}

type Hidden = {
  releaseView: (to: string[]) => Promise<void>;
  directoryEntry: (who: string) => Promise<DirectoryEntry>;
};
type Fetcher = { signedFetchHomes: (domain: string, method: string, path: string, body?: string, extra?: Record<string, string>) => Promise<Response> };

describe('requester proofs (Section 4.7)', () => {
  let w: Awaited<ReturnType<typeof world>>;
  beforeEach(async () => {
    w = await world();
    await (w.bobPhone as unknown as Hidden).releaseView(['alice@alpha.test']);
  });
  afterEach(async () => {
    await w.bed.close();
  });

  it('names a requester the same way at every address, so one user can be limited', () => {
    expect(requesterHash('Alice@alpha.test')).toEqual(requesterHash('alice@alpha.test'));
  });

  it('gives the released contact view to the requester who proves it', async () => {
    const entry = await (w.alicePhone as unknown as Hidden).directoryEntry('bob@beta.test');
    expect(entry.status === 'enrolled' && entry.view !== undefined).toBe(true);
  });

  it('answers at public level when the calling server names the requester without proof', async () => {
    const alpha = w.bed.server('alpha.test') as unknown as Fetcher;
    const hash = requesterHash('alice@alpha.test');
    const response = await alpha.signedFetchHomes('beta.test', 'GET', `/v0/directory/bob?requester=${encodeURIComponent(hash)}`);
    const entry = (await response.json()) as DirectoryEntry;
    expect(entry.status === 'enrolled' && entry.view === undefined).toBe(true);
  });

  it('shows the target no labels, scopes or limits of the requester’s clients, only what a contact view holds', async () => {
    const proofOf = (w.alicePhone as unknown as { requesterProof: (target: string) => Promise<string> }).requesterProof.bind(w.alicePhone);
    const decoded = Buffer.from(await proofOf('bob@beta.test'), 'base64url').toString('utf8');
    expect(decoded).not.toMatch(/"label"|"scopes"|"limits"|Phone/);
    const proof = JSON.parse(decoded) as { view: { view: { members: { kind: string }[] } } };
    expect(proof.view.view.members[0].kind).toBe('device');
    expect(decoded).not.toContain('"entries"');
  });

  it('refuses a proof signed for another target', async () => {
    const alpha = w.bed.server('alpha.test') as unknown as Fetcher;
    const proofOf = (w.alicePhone as unknown as { requesterProof: (target: string) => Promise<string> }).requesterProof.bind(w.alicePhone);
    const proof = await proofOf('carol@beta.test');
    const hash = requesterHash('alice@alpha.test');
    const response = await alpha.signedFetchHomes('beta.test', 'GET', `/v0/directory/bob?requester=${encodeURIComponent(hash)}`, '', { 'signet-requester': proof });
    const entry = (await response.json()) as DirectoryEntry;
    expect(entry.status === 'enrolled' && entry.view === undefined).toBe(true);
  });
});
