/**
 * Threads are MLS groups (RFC 9420), run by the Rust core in packages/mls on OpenMLS. Every leaf
 * uses its client's own certified Ed25519 key. The core never decides who is allowed in: it reports
 * the credentials a welcome or commit carries, Signet checks each against its owner's log, and only
 * then is the change applied.
 */
import { b64u, canonicalJson, fromB64u, utf8 } from './encoding';
import type { ClientKeys } from './identity';
import type { NativeMe, NativeMember } from './native';
import { native } from './native';

export const CIPHER_SUITE = 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519';

export class MlsError extends Error {}

export interface MemberIdentity {
  principal: string;
  clientId: string;
}

export interface Member extends MemberIdentity {
  leafIndex: number;
  signatureKey: string;
}

/** What a server hands out when someone claims one of a client's key packages. */
export interface ClaimedKeyPackage {
  clientId: string;
  kpId: string;
  keyPackage: string;
}

export interface Joiner {
  principal: string;
  clientId: string;
}

/** Just what's needed to add a client: whose it is and the key it must sign with. */
export interface MemberKeys {
  principal: string;
  clientId: string;
  sigKey: string;
}

export interface Addition {
  cert: MemberKeys;
  claimed: ClaimedKeyPackage;
}

/** Sender and changes a commit would make, before it's applied. */
export interface CommitPreview {
  sender: Member;
  added: Member[];
  removed: number[];
  selfRemoved: boolean;
}

const identityOf = (who: MemberIdentity): string => b64u(utf8(canonicalJson({ principal: who.principal, clientId: who.clientId })));

function memberOf(member: NativeMember): Member {
  try {
    const parsed = JSON.parse(fromB64u(member.identity).toString('utf8')) as Partial<MemberIdentity>;
    if (typeof parsed.principal === 'string' && typeof parsed.clientId === 'string') {
      return { principal: parsed.principal, clientId: parsed.clientId, leafIndex: member.leafIndex, signatureKey: member.signatureKey };
    }
  } catch {
    // fall through
  }
  throw new MlsError('member credential is not a Signet identity');
}

export const threadIdOf = (groupId: string): string => `t_${groupId}`;
const groupIdOf = (thread: string): string => {
  if (!thread.startsWith('t_')) throw new MlsError(`not a thread id: ${thread}`);
  return thread.slice(2);
};

/** A claimed key package must be validly signed with the key its certificate names, under the right identity. */
export function checkKeyPackage(cert: MemberKeys, claimed: ClaimedKeyPackage): void {
  let member: Member;
  try {
    member = memberOf(native().inspectKeyPackage(claimed.keyPackage));
  } catch (error) {
    throw new MlsError(`key package for ${cert.clientId} is invalid: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (member.principal !== cert.principal || member.clientId !== cert.clientId || claimed.clientId !== cert.clientId) {
    throw new MlsError(`key package does not belong to ${cert.principal}/${cert.clientId}`);
  }
  if (member.signatureKey !== cert.sigKey) throw new MlsError(`key package for ${cert.clientId} is not signed with its certified key`);
}

/** One client's MLS key store: its key packages and every group it's in, as one serialized blob. */
export class MlsSession {
  constructor(
    private readonly keys: ClientKeys,
    public state = '',
  ) {}

  private get me(): NativeMe {
    return { identity: identityOf(this.keys.cert), privateKey: this.keys.signing.privateKey, publicKey: this.keys.signing.publicKey };
  }

  keyPackage(lastResort = false): string {
    const { state, keyPackage } = native().keyPackage(this.state, this.me, lastResort);
    this.state = state;
    return keyPackage;
  }

  /** Start a group with these (already checked) clients. */
  createGroup(additions: Addition[]): { thread: string; welcome: string | null; joiners: Joiner[] } {
    additions.forEach(({ cert, claimed }) => checkKeyPackage(cert, claimed));
    const { state, groupId, welcome } = native().createGroup(this.state, this.me, additions.map((a) => a.claimed.keyPackage));
    this.state = state;
    return { thread: threadIdOf(groupId), welcome, joiners: additions.map(({ cert }) => ({ principal: cert.principal, clientId: cert.clientId })) };
  }

  commit(thread: string, removeLeaves: number[], additions: Addition[]): { commit: string; welcome: string | null; joiners: Joiner[] } {
    additions.forEach(({ cert, claimed }) => checkKeyPackage(cert, claimed));
    const { state, commit, welcome } = native().commit(this.state, groupIdOf(thread), this.me, removeLeaves, additions.map((a) => a.claimed.keyPackage));
    this.state = state;
    return { commit, welcome, joiners: additions.map(({ cert }) => ({ principal: cert.principal, clientId: cert.clientId })) };
  }

  /** Decrypt a welcome and list who's in the group, without joining. */
  peekWelcome(welcome: string): { thread: string; members: Member[] } {
    const { groupId, members } = native().peekWelcome(this.state, welcome);
    return { thread: threadIdOf(groupId), members: members.map(memberOf) };
  }

  join(welcome: string): { thread: string; members: Member[] } {
    const { state, groupId, members } = native().joinGroup(this.state, welcome);
    this.state = state;
    return { thread: threadIdOf(groupId), members: members.map(memberOf) };
  }

  encrypt(thread: string, plaintext: Uint8Array): string {
    const { state, message } = native().encrypt(this.state, groupIdOf(thread), this.me, b64u(plaintext));
    this.state = state;
    return message;
  }

  /** Report what a commit would change without applying it. */
  previewCommit(thread: string, message: string): CommitPreview {
    const result = native().process(this.state, groupIdOf(thread), message, false);
    if (result.kind !== 'commit') throw new MlsError('expected a commit');
    return { sender: memberOf(result.sender), added: result.added.map(memberOf), removed: result.removed, selfRemoved: result.selfRemoved };
  }

  applyCommit(thread: string, message: string): CommitPreview {
    const result = native().process(this.state, groupIdOf(thread), message, true);
    if (result.kind !== 'commit') throw new MlsError('expected a commit');
    this.state = result.state;
    return { sender: memberOf(result.sender), added: result.added.map(memberOf), removed: result.removed, selfRemoved: result.selfRemoved };
  }

  decrypt(thread: string, message: string): { sender: Member; plaintext: Buffer } {
    const result = native().process(this.state, groupIdOf(thread), message, false);
    if (result.kind !== 'application' || result.plaintext === null) throw new MlsError('expected an application message');
    this.state = result.state;
    return { sender: memberOf(result.sender), plaintext: fromB64u(result.plaintext) };
  }

  members(thread: string): Member[] {
    return native().members(this.state, groupIdOf(thread)).map(memberOf);
  }

  epoch(thread: string): number {
    return native().epoch(this.state, groupIdOf(thread));
  }

  isActive(thread: string): boolean {
    return native().isActive(this.state, groupIdOf(thread));
  }

  /** RFC 9420 exporter: a secret only the thread's current members can derive. */
  exportSecret(thread: string, label: string, length = 32): Buffer {
    return fromB64u(native().exportSecret(this.state, groupIdOf(thread), label, length));
  }
}
