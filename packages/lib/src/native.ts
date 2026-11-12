import { join } from 'node:path';

export interface NativeMember {
  leafIndex: number;
  identity: string;
  signatureKey: string;
}

export interface NativeMe {
  identity: string;
  privateKey: string;
  publicKey: string;
}

/** The Node addon built from packages/mls: MLS (OpenMLS) and ECVRF. See its README. */
export interface NativeSignet {
  keyPackage(state: string, me: NativeMe, lastResort: boolean): { state: string; keyPackage: string };
  inspectKeyPackage(keyPackage: string): NativeMember;
  createGroup(state: string, me: NativeMe, keyPackages: string[]): { state: string; groupId: string; welcome: string | null };
  commit(state: string, groupId: string, me: NativeMe, remove: number[], add: string[]): { state: string; commit: string; welcome: string | null };
  peekWelcome(state: string, welcome: string): { groupId: string; members: NativeMember[] };
  joinGroup(state: string, welcome: string): { state: string; groupId: string; members: NativeMember[] };
  encrypt(state: string, groupId: string, me: NativeMe, plaintext: string): { state: string; message: string };
  process(
    state: string,
    groupId: string,
    message: string,
    apply: boolean,
  ): {
    kind: 'application' | 'commit';
    state: string;
    sender: NativeMember;
    plaintext: string | null;
    added: NativeMember[];
    removed: number[];
    selfRemoved: boolean;
    applied: boolean;
  };
  members(state: string, groupId: string): NativeMember[];
  epoch(state: string, groupId: string): number;
  isActive(state: string, groupId: string): boolean;
  exportSecret(state: string, groupId: string, label: string, length: number): string;
  vrfKeygen(): { secret: string; public: string };
  vrfProve(secret: string, alpha: string): { proof: string; output: string };
  vrfVerify(publicKey: string, alpha: string, proof: string): string;
  /** SPAKE2 (Ed25519 group). Side "a" is the account owner, "b" the new client. */
  Pake: new (side: 'a' | 'b', password: string, idA: string, idB: string) => { readonly message: string; finish(inbound: string): string };
}

let addon: NativeSignet | undefined;

/** SIGNET_MLS_ADDON overrides the path, e.g. when the addon ships next to a bundled app. */
export function native(): NativeSignet {
  addon ??= require(process.env.SIGNET_MLS_ADDON ?? join(__dirname, '../../mls/signet_mls.node')) as NativeSignet;
  return addon;
}
