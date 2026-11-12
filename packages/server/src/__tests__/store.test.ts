import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Store, UserRecord } from '../store';
import { MemoryStore, SqliteStore } from '../store';

const item = (id: string) => ({ id, kind: 'request' as const, from: 'alice@alpha.test', payload: { n: id } });
const record = (key: string) => ({ binding: { principal: 'bob@beta.test', identityKey: key, ts: 't', sig: 's' }, log: [], card: {}, view: {} }) as unknown as UserRecord;

let dir: string;

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), 'signet-store-'));
});

afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

// The same contract for both stores: what the server relies on, change by change.
describe.each([
  ['memory', () => new MemoryStore()],
  ['sqlite', () => new SqliteStore(join(dir, `${Math.random().toString(36).slice(2)}.db`))],
])('%s store', (_name, make: () => Store) => {
  let store: Store;

  beforeEach(() => {
    store = make();
  });

  afterEach(() => {
    store.close();
  });

  it('keeps users, and hands back copies rather than live objects', () => {
    store.putUser('bob', record('k1'));
    const user = store.user('bob');
    if (!user) throw new Error('expected bob');
    user.binding.identityKey = 'changed';

    expect(store.user('bob')?.binding.identityKey).toBe('k1');
    expect(store.hasUser('bob')).toBe(true);
    expect(store.userLocals()).toEqual(['bob']);
    store.deleteUser('bob');
    expect(store.hasUser('bob')).toBe(false);
  });

  it('numbers mail per user and reads it after a cursor', () => {
    store.push('bob', item('a'));
    store.push('bob', item('b'));
    store.push('carol', item('c'));

    expect(store.mailbox('bob').map((mail) => [mail.seq, mail.id])).toEqual([[1, 'a'], [2, 'b']]);
    expect(store.mailbox('bob', 1).map((mail) => mail.id)).toEqual(['b']);
    expect(store.mailbox('carol').map((mail) => mail.seq)).toEqual([1]);
  });

  it('hands out key packages once each, oldest first, then the last-resort one', () => {
    store.addKeyPackages('c1', [{ kpId: 'k1', keyPackage: 'p1' }, { kpId: 'k2', keyPackage: 'p2' }]);
    store.setLastResort('c1', { kpId: 'last', keyPackage: 'pl' });

    expect(store.countKeyPackages('c1')).toBe(2);
    expect([store.claimKeyPackage('c1'), store.claimKeyPackage('c1'), store.claimKeyPackage('c1'), store.claimKeyPackage('c1')].map((kp) => kp?.kpId)).toEqual(['k1', 'k2', 'last', 'last']);
    expect(store.claimKeyPackage('other')).toBeUndefined();
  });

  it('parks sealed deliveries up to a cap and releases them in order', () => {
    expect(store.park('bob', 'h1', item('p1'), 60_000, 2)).toBe(true);
    expect(store.park('bob', 'h2', item('p2'), 60_000, 2)).toBe(true);
    expect(store.park('bob', 'h1', item('p3'), 60_000, 2)).toBe(false);

    expect(store.release('bob', ['h2', 'h1'])).toBe(2);
    expect(store.mailbox('bob').map((mail) => mail.id)).toEqual(['p1', 'p2']);
    expect(store.release('bob', ['h1'])).toBe(0);
  });

  it('spends tokens once, counts per day, and answers first-use once per window', () => {
    expect([store.spend('n1'), store.spend('n1')]).toEqual([true, false]);
    expect([store.bump('x'), store.bump('x', 10), store.count('x'), store.count('y')]).toEqual([1, 11, 11, 0]);
    expect([store.replays.firstUse('r'), store.replays.firstUse('r'), store.recoveryProofs.firstUse('r')]).toEqual([true, false, true]);
    expect(store.replays.firstUse('r', Date.now() + 11 * 60_000)).toBe(true);
  });

  it('keeps tokens, view grants, contacts, claims, server keys and queued deliveries', () => {
    store.updateTokens('bob', ['t1', 't2'], []);
    store.updateTokens('bob', [], ['t1']);
    store.updateViewGrants('bob', ['v1'], []);
    store.addContacts('bob', ['Alice@Alpha.test'], ['Alpha.test']);
    store.setClaims('bob', ['team:corporate']);
    store.putBlob('b1', Buffer.from('ciphertext'));
    store.saveOutbound({ id: 'o1', domain: 'alpha.test', delivery: { id: 'd' }, sender: 'bob@beta.test', attempt: 2, dueAt: 5, reason: 'down' });

    expect([store.hasToken('bob', 't1'), store.hasToken('bob', 't2'), store.hasViewGrant('bob', 'v1')]).toEqual([false, true, true]);
    expect(store.contactsOf('bob')).toEqual({ contacts: ['alice@alpha.test'], trustedDomains: ['alpha.test'] });
    expect(store.claims('bob')).toEqual(['team:corporate']);
    expect(store.blob('b1')?.toString()).toBe('ciphertext');
    expect(store.outbound()).toEqual([expect.objectContaining({ id: 'o1', attempt: 2 })]);
    store.removeOutbound('o1');
    expect(store.outbound()).toEqual([]);
  });
});

describe('sqlite store on disk', () => {
  it('has everything after reopening the file', () => {
    const file = join(dir, 'reopen.db');
    const first = new SqliteStore(file);
    first.putUser('bob', record('k1'));
    first.push('bob', item('a'));
    first.replays.firstUse('sig');
    first.close();

    const second = new SqliteStore(file);
    expect(second.user('bob')?.binding.identityKey).toBe('k1');
    expect(second.mailbox('bob').map((mail) => mail.id)).toEqual(['a']);
    expect(second.replays.firstUse('sig')).toBe(false);
    second.close();
  });
});
