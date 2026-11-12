import { generateSigningKey } from '../crypto';
import { fromB64u } from '../encoding';
import type { LogLeaf } from '../transparency';
import {
  MerkleLog,
  TransparencyError,
  hashLeaf,
  leafBytes,
  verifyConsistency,
  verifyInclusion,
  verifyLeaf,
  verifyTreeHead,
} from '../transparency';

const leaf = (address: string, head: string): LogLeaf => ({
  v: 0,
  index: `vrf:${address}`,
  domain: address.split('@')[1],
  kind: 'bound',
  identityKey: 'ik',
  cardHash: head,
  viewHash: null,
  ts: '2026-11-11T00:00:00.000Z',
});

function filledLog(size: number) {
  const log = new MerkleLog(generateSigningKey());
  const leaves = Array.from({ length: size }, (_, i) => leaf(`user${i % 3}@beta.test`, `h${i}`));
  leaves.forEach((entry) => log.append(entry));
  return { log, leaves };
}

describe('Merkle log', () => {
  it('proves every leaf is included, for every tree size up to 17', () => {
    for (let size = 1; size <= 17; size += 1) {
      const { log, leaves } = filledLog(size);
      const head = log.treeHead();
      leaves.forEach((entry, index) => {
        expect(verifyInclusion(hashLeaf(leafBytes(entry)), log.inclusion(index), fromB64u(head.root))).toBe(true);
      });
    }
  });

  it('proves every earlier tree is a prefix of every later one', () => {
    const { log } = filledLog(17);
    for (let second = 1; second <= 17; second += 1) {
      const later = log.treeHead(second);
      for (let first = 1; first <= second; first += 1) {
        const earlier = log.treeHead(first);
        expect(verifyConsistency(first, second, fromB64u(earlier.root), fromB64u(later.root), log.consistency(first, second))).toBe(true);
      }
    }
  });

  it('rejects a tampered leaf and a forked history', () => {
    const { log, leaves } = filledLog(9);
    const head = log.treeHead();
    const forged = { ...leaves[4], identityKey: 'someone-else' };
    expect(verifyInclusion(hashLeaf(leafBytes(forged)), log.inclusion(4), fromB64u(head.root))).toBe(false);

    const { log: fork } = filledLog(5);
    fork.append(leaf('mallory@beta.test', 'x'));
    expect(verifyConsistency(5, 9, fromB64u(fork.treeHead(5).root), fromB64u(head.root), log.consistency(5, 9))).toBe(true);
    expect(verifyConsistency(6, 9, fromB64u(fork.treeHead(6).root), fromB64u(head.root), log.consistency(6, 9))).toBe(false);
  });

  it('serves the latest leaf and full history per address under a signed head', () => {
    const { log } = filledLog(10);
    const latest = log.latest('beta.test', 'vrf:user1@beta.test');
    if (!latest.leaf || !latest.proof) throw new Error('expected a leaf');

    expect(latest.leaf.cardHash).toBe('h7');
    expect(verifyTreeHead(log.publicKey, latest.head)).toBe(true);
    expect(() => verifyLeaf({ url: 'log', key: log.publicKey }, latest.leaf as LogLeaf, latest.proof as never, latest.head)).not.toThrow();
    expect(log.latest('alpha.test', 'vrf:user1@beta.test').leaf).toBeNull();
    expect(log.history('beta.test', 'vrf:user1@beta.test').map((entry) => entry.leaf.cardHash)).toEqual(['h1', 'h4', 'h7']);
    expect(() => verifyLeaf({ url: 'log', key: generateSigningKey().publicKey }, latest.leaf as LogLeaf, latest.proof as never, latest.head)).toThrow(
      TransparencyError,
    );
  });
});
