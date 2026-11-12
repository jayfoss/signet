import type { ClientCert, EnrollmentRequest } from '@signet/lib';
import {
  EnrollmentError,
  HttpPairingChannel,
  Identity,
  enrollmentFingerprint,
  enrollmentLink,
  fetchApprovedCert,
  joinPairing,
  pairAsOwner,
  parseEnrollmentLink,
  parsePairingCode,
  requestEnrollment,
} from '@signet/lib';
import { Testbed } from '../testbed';

async function world() {
  const bed = await Testbed.start(['alpha.test', 'beta.test']);
  const alice = Identity.create('alice@alpha.test');
  const phone = bed.client(alice.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] }));
  const jerzy = Identity.create('jerzy@beta.test');
  const jerzyPhone = bed.client(jerzy.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send', 'admit'] }));
  await bed.publish(alice);
  await bed.publish(jerzy);
  await phone.ready();
  await jerzyPhone.ready();
  /** What the owner's device does on approval: certify with its own choice of scopes, then publish. */
  const approve = (scopes: string[]) => async (request: EnrollmentRequest): Promise<ClientCert> => {
    const cert = alice.approveClient(request, { scopes });
    await bed.publish(alice);
    return cert;
  };
  return { bed, alice, phone, jerzyPhone, approve };
}

describe('enrolling a client whose keys never leave it', () => {
  let w: Awaited<ReturnType<typeof world>>;

  beforeEach(async () => {
    w = await world();
  });

  afterEach(async () => {
    await w.bed.close();
  });

  it('enrolls from a QR code or link, with the scopes the owner chooses', async () => {
    const { bed, phone, jerzyPhone, approve } = w;
    const pending = requestEnrollment('alice@alpha.test', { kind: 'agent', label: 'Assistant', scopes: ['read:*', 'send', 'admit', 'intent:*'] });
    await expect(fetchApprovedCert(bed.resolver, pending)).rejects.toThrow('not approved yet');

    const scanned = parseEnrollmentLink(enrollmentLink(pending.request));
    expect(enrollmentFingerprint(scanned)).toBe(enrollmentFingerprint(pending.request));
    await approve(['read:*', 'send'])(scanned);

    const keys = await fetchApprovedCert(bed.resolver, pending);
    expect(keys.cert).toMatchObject({ clientId: pending.request.body.clientId, kind: 'agent', scopes: ['read:*', 'send'] });
    expect(keys.signing).toBe(pending.signing);
    const assistant = bed.client(keys);
    await assistant.ready();
    await assistant.sendRequest('jerzy@beta.test', { subject: 'Hello from the assistant' });
    expect(await jerzyPhone.sync()).toMatchObject([{ kind: 'request', request: { body: { fromClient: keys.cert.clientId } } }]);
    expect(phone).toBeDefined();
  });

  it('refuses a request whose scopes or keys were changed on the way, and says so in the fingerprint', () => {
    const pending = requestEnrollment('alice@alpha.test', { kind: 'agent', label: 'Assistant', scopes: ['send'] });
    const tampered = { ...pending.request, body: { ...pending.request.body, scopes: ['read:*', 'send', 'intent:*'] } };

    expect(enrollmentFingerprint(tampered)).not.toBe(enrollmentFingerprint(pending.request));
    expect(() => w.alice.approveClient(tampered)).toThrow('not signed by the key it names');
    expect(() => w.alice.approveClient(requestEnrollment('mallory@alpha.test', { kind: 'device', label: 'X', scopes: [] }).request)).toThrow('is for mallory');
  });

  it('pairs a new client with a code, the server only relaying', async () => {
    const { bed, phone, approve } = w;
    const { code, channel } = await phone.openPairing();
    const shown: string[] = [];

    const [cert, keys] = await Promise.all([
      pairAsOwner(channel, 'alice@alpha.test', code, async (request, fingerprint) => {
        shown.push(fingerprint);
        return approve(['read:*', 'send', 'admit'])(request);
      }),
      joinPairing(bed.resolver, 'alice@alpha.test', code, { kind: 'device', label: 'Laptop', scopes: ['read:*', 'send', 'admit'] }, (fingerprint) => shown.push(fingerprint)),
    ]);

    expect(shown[0]).toBe(shown[1]);
    expect(keys.cert).toEqual(cert);
    const laptop = bed.client(keys);
    await laptop.ready();
    expect((await laptop.monitor()).newClients).toEqual([]);
  });

  it('fails on a wrong code without enrolling anything, and the slot is then used up', async () => {
    const { bed, phone, alice, approve } = w;
    const { code, channel } = await phone.openPairing();
    const { slot } = parsePairingCode(code);
    const wrong = `${slot}-AAAA-AAAA`;
    const entries = alice.entries.length;

    const [owner, newcomer] = await Promise.allSettled([
      pairAsOwner(channel, 'alice@alpha.test', code, approve(['send'])),
      joinPairing(bed.resolver, 'alice@alpha.test', wrong, { kind: 'device', label: 'Laptop', scopes: [] }),
    ]);

    expect(owner).toMatchObject({ status: 'rejected', reason: expect.objectContaining({ message: expect.stringContaining('different code') }) });
    expect(newcomer).toMatchObject({ status: 'rejected', reason: expect.objectContaining({ message: expect.stringContaining('different code') }) });
    expect(alice.entries).toHaveLength(entries);
    await expect(new HttpPairingChannel(bed.url('alpha.test'), slot, 'b').send('another guess')).rejects.toThrow('409');
  });

  it('tells the new client when the owner declines', async () => {
    const { bed, phone } = w;
    const { code, channel } = await phone.openPairing();

    const [, newcomer] = await Promise.allSettled([
      pairAsOwner(channel, 'alice@alpha.test', code, async () => null),
      joinPairing(bed.resolver, 'alice@alpha.test', code, { kind: 'agent', label: 'Unknown', scopes: [] }),
    ]);

    expect(newcomer).toMatchObject({ status: 'rejected', reason: expect.any(EnrollmentError) });
  });

  it("lets only the account's devices open a slot or speak for the owner in it", async () => {
    const { bed, alice, phone } = w;
    const agent = bed.client(alice.enrollClient({ kind: 'agent', label: 'Assistant', scopes: ['send'] }));
    await bed.publish(alice);
    await agent.ready();

    await expect(agent.openPairing()).rejects.toThrow('403');
    const { code } = await phone.openPairing();
    await expect(new HttpPairingChannel(bed.url('alpha.test'), parsePairingCode(code).slot, 'a').send('pretend owner')).rejects.toThrow('401');
  });
});
