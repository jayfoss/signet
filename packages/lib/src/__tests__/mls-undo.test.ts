import { MlsSession } from '../mls';
import { Identity } from '../identity';

/** Two clients in one group: the joiner takes a welcome, goes back to before it, and can take another. */
describe('undoing MLS changes (Section 8.8)', () => {
  const setup = () => {
    const alice = Identity.create('alice@alpha.test');
    const bob = Identity.create('bob@beta.test');
    const aliceKeys = alice.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send'] });
    const bobKeys = bob.enrollClient({ kind: 'device', label: 'Phone', scopes: ['read:*', 'send'] });
    const a = new MlsSession(aliceKeys);
    const b = new MlsSession(bobKeys);
    const cert = (keys: typeof bobKeys) => ({ principal: keys.cert.principal, clientId: keys.cert.clientId, sigKey: keys.cert.sigKey });
    const claim = (session: MlsSession, keys: typeof bobKeys) => ({ cert: cert(keys), claimed: { clientId: keys.cert.clientId, kpId: 'kp', keyPackage: session.keyPackage() } });
    return { a, b, bobKeys, claim };
  };

  it('takes a join back, after which the same welcome can be taken again', () => {
    const { a, b, bobKeys, claim } = setup();
    const created = a.createGroup([claim(b, bobKeys)]);
    const joined = b.joinUndoable(created.welcome as string);
    expect(b.members(joined.thread)).toHaveLength(2);
    b.rollback(joined.undo);
    expect(() => b.members(joined.thread)).toThrow();
    expect(b.joinUndoable(created.welcome as string).thread).toBe(joined.thread);
  });

  it('takes a commit back, leaving other state alone', () => {
    const { a, b, bobKeys, claim } = setup();
    const first = a.createGroup([claim(b, bobKeys)]);
    b.join(first.welcome as string);
    const epoch = a.epoch(first.thread);
    const commit = a.commitUndoable(first.thread, [], []);
    expect(a.epoch(first.thread)).toBe(epoch + 1);
    a.rollback(commit.undo);
    expect(a.epoch(first.thread)).toBe(epoch);
    // The undone commit's own wire message is still good for the member who has not applied anything.
    expect(b.previewCommit(first.thread, commit.commit).sender.clientId).toBeDefined();
  });
});
