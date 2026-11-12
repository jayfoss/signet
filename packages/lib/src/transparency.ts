/**
 * The transparency log: an append-only Merkle tree (RFC 9162 hashing and proofs) of every directory
 * change. A server can't show one key to some people and another key to others, or quietly rebind
 * an address, without leaving a public record its owner's devices will see.
 */
import type { KeyPair } from './crypto';
import { sha256Bytes, signJson, verifyJson } from './crypto';
import { b64u, canonicalJson, fromB64u, utf8 } from './encoding';

/**
 * One directory change, at the address's VRF index (only its domain can compute it). The leaf commits to
 * the public card and contact view, never their contents.
 */
export interface LogLeaf {
  v: 0;
  index: string;
  domain: string;
  kind: 'bound' | 'unbound';
  identityKey: string | null;
  cardHash: string | null;
  viewHash: string | null;
  ts: string;
}

/** A signed tree head: the log's commitment to its first `size` leaves. */
export interface TreeHead {
  size: number;
  root: string;
  ts: string;
  sig: string;
}

export interface InclusionProof {
  leafIndex: number;
  treeSize: number;
  path: string[];
}

/** What the log returns for "the latest leaf for this address", with the proof that it's in the tree. */
export interface LatestLeaf {
  leaf: LogLeaf | null;
  proof: InclusionProof | null;
  head: TreeHead;
}

export interface TrustedLog {
  url: string;
  key: string;
}

export class TransparencyError extends Error {}

export const leafBytes = (leaf: LogLeaf): Buffer => utf8(canonicalJson(leaf));

const LEAF = Uint8Array.of(0);
const NODE = Uint8Array.of(1);
export const hashLeaf = (data: Uint8Array): Buffer => sha256Bytes(LEAF, data);
const hashNode = (left: Uint8Array, right: Uint8Array): Buffer => sha256Bytes(NODE, left, right);
const EMPTY_ROOT = sha256Bytes();

/** Largest power of two strictly less than n (n > 1). */
const split = (n: number): number => {
  let k = 1;
  while (k << 1 < n) k <<= 1;
  return k;
};

export function merkleRoot(leaves: Buffer[]): Buffer {
  if (leaves.length === 0) return EMPTY_ROOT;
  if (leaves.length === 1) return leaves[0];
  const k = split(leaves.length);
  return hashNode(merkleRoot(leaves.slice(0, k)), merkleRoot(leaves.slice(k)));
}

/** RFC 9162 2.1.3.1: the audit path for leaf m in a tree of these leaf hashes. */
export function inclusionPath(m: number, leaves: Buffer[]): Buffer[] {
  if (leaves.length <= 1) return [];
  const k = split(leaves.length);
  return m < k
    ? [...inclusionPath(m, leaves.slice(0, k)), merkleRoot(leaves.slice(k))]
    : [...inclusionPath(m - k, leaves.slice(k)), merkleRoot(leaves.slice(0, k))];
}

function subproof(m: number, leaves: Buffer[], whole: boolean): Buffer[] {
  if (m === leaves.length) return whole ? [] : [merkleRoot(leaves)];
  const k = split(leaves.length);
  return m <= k
    ? [...subproof(m, leaves.slice(0, k), whole), merkleRoot(leaves.slice(k))]
    : [...subproof(m - k, leaves.slice(k), false), merkleRoot(leaves.slice(0, k))];
}

/** RFC 9162 2.1.4.1: proof that the first m leaves are a prefix of these leaves. */
export const consistencyPath = (m: number, leaves: Buffer[]): Buffer[] =>
  m === 0 || m === leaves.length ? [] : subproof(m, leaves, true);

/** RFC 9162 2.1.3.2. */
export function verifyInclusion(leafHash: Uint8Array, proof: InclusionProof, root: Uint8Array): boolean {
  if (proof.leafIndex >= proof.treeSize) return false;
  let fn = proof.leafIndex;
  let sn = proof.treeSize - 1;
  let r = Buffer.from(leafHash);
  for (const p of proof.path.map(fromB64u)) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = hashNode(p, r);
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) {
          fn >>= 1;
          sn >>= 1;
        }
      }
    } else {
      r = hashNode(r, p);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 && r.equals(Buffer.from(root));
}

/** RFC 9162 2.1.4.2. */
export function verifyConsistency(
  first: number,
  second: number,
  firstRoot: Uint8Array,
  secondRoot: Uint8Array,
  path: string[],
): boolean {
  if (first > second) return false;
  if (first === second) return path.length === 0 && Buffer.from(firstRoot).equals(Buffer.from(secondRoot));
  if (first === 0) return true;
  if (path.length === 0) return false;
  let nodes = path.map(fromB64u);
  if ((first & (first - 1)) === 0) nodes = [Buffer.from(firstRoot), ...nodes];
  let fn = first - 1;
  let sn = second - 1;
  while (fn % 2 === 1) {
    fn >>= 1;
    sn >>= 1;
  }
  let fr = nodes[0];
  let sr = nodes[0];
  for (const c of nodes.slice(1)) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      fr = hashNode(c, fr);
      sr = hashNode(c, sr);
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) {
          fn >>= 1;
          sn >>= 1;
        }
      }
    } else {
      sr = hashNode(sr, c);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 && fr.equals(Buffer.from(firstRoot)) && sr.equals(Buffer.from(secondRoot));
}

export function signTreeHead(key: KeyPair, size: number, root: Uint8Array, now = new Date()): TreeHead {
  const unsigned = { size, root: b64u(root), ts: now.toISOString() };
  return { ...unsigned, sig: signJson(key, { type: 'tree-head', ...unsigned }) };
}

export function verifyTreeHead(logKey: string, head: TreeHead): boolean {
  const { sig, ...unsigned } = head;
  return verifyJson(logKey, { type: 'tree-head', ...unsigned }, sig);
}

/** An in-memory log. The server app wraps it in HTTP; tests use it directly. */
export class MerkleLog {
  private readonly leaves: LogLeaf[] = [];
  private readonly hashes: Buffer[] = [];
  /** Leaves filed by `domain index`: one domain can't put a leaf where another's address will be looked up. */
  private readonly byAddress = new Map<string, number[]>();

  constructor(private readonly key: KeyPair) {}

  get publicKey(): string {
    return this.key.publicKey;
  }

  get size(): number {
    return this.leaves.length;
  }

  append(leaf: LogLeaf): number {
    const index = this.leaves.length;
    this.leaves.push(leaf);
    this.hashes.push(hashLeaf(leafBytes(leaf)));
    const key = leafKey(leaf.domain, leaf.index);
    this.byAddress.set(key, [...(this.byAddress.get(key) ?? []), index]);
    return index;
  }

  treeHead(size = this.leaves.length): TreeHead {
    return signTreeHead(this.key, size, merkleRoot(this.hashes.slice(0, size)));
  }

  inclusion(leafIndex: number, treeSize = this.leaves.length): InclusionProof {
    if (leafIndex >= treeSize || treeSize > this.leaves.length) throw new TransparencyError('no such leaf');
    return { leafIndex, treeSize, path: inclusionPath(leafIndex, this.hashes.slice(0, treeSize)).map(b64u) };
  }

  consistency(first: number, second = this.leaves.length): string[] {
    if (first > second || second > this.leaves.length) throw new TransparencyError('no such tree sizes');
    return consistencyPath(first, this.hashes.slice(0, second)).map(b64u);
  }

  latest(domain: string, index: string): LatestLeaf {
    const head = this.treeHead();
    const at = this.byAddress.get(leafKey(domain, index))?.at(-1);
    if (at === undefined) return { leaf: null, proof: null, head };
    return { leaf: this.leaves[at], proof: this.inclusion(at, head.size), head };
  }

  history(domain: string, index: string): { leaf: LogLeaf; proof: InclusionProof }[] {
    const size = this.leaves.length;
    return (this.byAddress.get(leafKey(domain, index)) ?? []).map((at) => ({ leaf: this.leaves[at], proof: this.inclusion(at, size) }));
  }
}

const leafKey = (domain: string, index: string): string => `${domain.toLowerCase()} ${index}`;

/** Every log answer about an address must be about that address's own domain. */
export function checkLeafDomain(leaf: LogLeaf | null, domain: string): void {
  if (leaf && leaf.domain.toLowerCase() !== domain.toLowerCase()) throw new TransparencyError(`the log answered with a leaf from ${leaf.domain}, not ${domain}`);
}

/** Check a leaf, its proof and the signed head together. */
export function verifyLeaf(log: TrustedLog, leaf: LogLeaf, proof: InclusionProof, head: TreeHead): void {
  if (!verifyTreeHead(log.key, head)) throw new TransparencyError('tree head is not signed by the log');
  if (proof.treeSize !== head.size) throw new TransparencyError('proof is for a different tree size');
  if (!verifyInclusion(hashLeaf(leafBytes(leaf)), proof, fromB64u(head.root))) {
    throw new TransparencyError('leaf is not in the log');
  }
}
