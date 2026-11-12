/**
 * Privacy Pass (RFC 9576/9577) publicly verifiable tokens, type 0x0002 (RFC 9578), on RSA blind
 * signatures (RFC 9474, RSABSSA-SHA384-PSS-Deterministic).
 *
 * In Signet the sender's home server is the attester: it knows its user and rate-limits them. A
 * separate issuer signs blinded token requests from attesters it trusts, never seeing the token. The
 * recipient's server is the origin: it accepts a first-contact request carrying a valid, unspent token
 * bound to its own domain, so it learns "a rate-limited Signet user sent this" and nothing about who.
 */
import type { KeyObject } from 'node:crypto';
import { constants, createHash, createPrivateKey, createPublicKey, generateKeyPairSync, privateDecrypt, randomBytes, verify } from 'node:crypto';
import { b64u, fromB64u } from './encoding';

export const TOKEN_TYPE = 0x0002;
const HASH_LEN = 48;
const SALT_LEN = 48;

export interface IssuerKey {
  name: string;
  /** DER SubjectPublicKeyInfo, base64url. */
  publicKey: string;
}

export interface IssuerKeyPair extends IssuerKey {
  privateKey: KeyObject;
}

export class TokenError extends Error {}

const sha256 = (...parts: Uint8Array[]): Buffer => {
  const hash = createHash('sha256');
  parts.forEach((part) => hash.update(part));
  return hash.digest();
};
const sha384 = (...parts: Uint8Array[]): Buffer => {
  const hash = createHash('sha384');
  parts.forEach((part) => hash.update(part));
  return hash.digest();
};

const toBig = (bytes: Uint8Array): bigint => BigInt(`0x${Buffer.from(bytes).toString('hex') || '0'}`);
function toBytes(value: bigint, length: number): Buffer {
  const hex = value.toString(16).padStart(length * 2, '0');
  if (hex.length > length * 2) throw new TokenError('integer too large');
  return Buffer.from(hex, 'hex');
}

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n;
  let b = base % modulus;
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % modulus;
    b = (b * b) % modulus;
    e >>= 1n;
  }
  return result;
}

function modInverse(a: bigint, modulus: bigint): bigint | null {
  let [oldR, r] = [a % modulus, modulus];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  if (oldR !== 1n) return null;
  return ((oldS % modulus) + modulus) % modulus;
}

function publicParts(publicKey: string): { key: KeyObject; n: bigint; e: bigint; length: number } {
  const key = createPublicKey({ key: fromB64u(publicKey), format: 'der', type: 'spki' });
  const jwk = key.export({ format: 'jwk' });
  const nBytes = fromB64u(jwk.n as string);
  return { key, n: toBig(nBytes), e: toBig(fromB64u(jwk.e as string)), length: nBytes.length };
}

function mgf1(seed: Uint8Array, length: number): Buffer {
  const blocks: Buffer[] = [];
  for (let counter = 0; blocks.length * HASH_LEN < length; counter += 1) {
    const c = Buffer.alloc(4);
    c.writeUInt32BE(counter);
    blocks.push(sha384(seed, c));
  }
  return Buffer.concat(blocks).subarray(0, length);
}

/** EMSA-PSS-ENCODE (RFC 8017 §9.1.1) with SHA-384, MGF1-SHA-384 and a 48-byte salt. */
function pssEncode(message: Uint8Array, emBits: number): Buffer {
  const emLen = Math.ceil(emBits / 8);
  const salt = randomBytes(SALT_LEN);
  const h = sha384(Buffer.alloc(8), sha384(message), salt);
  const db = Buffer.concat([Buffer.alloc(emLen - SALT_LEN - HASH_LEN - 2), Buffer.from([1]), salt]);
  const mask = mgf1(h, db.length);
  const masked = Buffer.from(db.map((byte, i) => byte ^ mask[i]));
  masked[0] &= 0xff >> (8 * emLen - emBits);
  return Buffer.concat([masked, h, Buffer.from([0xbc])]);
}

export function generateIssuerKey(name: string): IssuerKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return { name, privateKey, publicKey: b64u(publicKey.export({ format: 'der', type: 'spki' })) };
}

/** An issuer key as JSON, to keep across restarts: tokens it signed stay valid only while the key does. */
export function exportIssuerKey(key: IssuerKeyPair): { name: string; publicKey: string; privateKey: string } {
  return { name: key.name, publicKey: key.publicKey, privateKey: key.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString() };
}

export function importIssuerKey(saved: { name: string; publicKey: string; privateKey: string }): IssuerKeyPair {
  return { name: saved.name, publicKey: saved.publicKey, privateKey: createPrivateKey(saved.privateKey) };
}

/**
 * RFC 9578 derives the key id from an id-RSASSA-PSS SubjectPublicKeyInfo; this uses the plain RSA
 * SPKI, which identifies the same key. Interop with other Privacy Pass stacks would need the exact form.
 */
export const tokenKeyId = (publicKey: string): Buffer => sha256(fromB64u(publicKey));

/** RFC 9577 §2.1 TokenChallenge, with no redemption context (tokens are bound to the origin, not a session). */
export function encodeChallenge(issuerName: string, originInfo: string): Buffer {
  const issuer = Buffer.from(issuerName, 'utf8');
  const origin = Buffer.from(originInfo, 'utf8');
  const u16 = (value: number) => {
    const out = Buffer.alloc(2);
    out.writeUInt16BE(value);
    return out;
  };
  return Buffer.concat([u16(TOKEN_TYPE), u16(issuer.length), issuer, Buffer.from([0]), u16(origin.length), origin]);
}

const tokenInput = (nonce: Uint8Array, challengeDigest: Uint8Array, keyId: Uint8Array): Buffer => {
  const type = Buffer.alloc(2);
  type.writeUInt16BE(TOKEN_TYPE);
  return Buffer.concat([type, nonce, challengeDigest, keyId]);
};

/** What a client keeps between sending a blinded request and finalizing the token. */
export interface PendingToken {
  issuer: IssuerKey;
  input: string;
  inverse: string;
  blinded: string;
}

/** Client: prepare a token request for one origin. Only `blinded` leaves the client. */
export function blindTokenRequest(issuer: IssuerKey, origin: string): PendingToken {
  const { n, e, length } = publicParts(issuer.publicKey);
  const input = tokenInput(randomBytes(32), sha256(encodeChallenge(issuer.name, origin)), tokenKeyId(issuer.publicKey));
  const m = toBig(pssEncode(input, n.toString(2).length - 1));
  for (;;) {
    const r = toBig(randomBytes(length)) % n;
    const inverse = r > 1n ? modInverse(r, n) : null;
    if (!inverse) continue;
    const z = (m * modPow(r, e, n)) % n;
    return { issuer, input: b64u(input), inverse: inverse.toString(16), blinded: b64u(toBytes(z, length)) };
  }
}

/** Issuer: sign a blinded message without learning what it is. Checks its own result against fault attacks. */
export function blindSign(issuer: IssuerKeyPair, blinded: string): string {
  const { n, e, length } = publicParts(issuer.publicKey);
  const z = fromB64u(blinded);
  if (z.length !== length || toBig(z) >= n) throw new TokenError('blinded message is out of range');
  const s = privateDecrypt({ key: issuer.privateKey, padding: constants.RSA_NO_PADDING }, z);
  if (modPow(toBig(s), e, n) !== toBig(z)) throw new TokenError('signing failed its own check');
  return b64u(s);
}

/** Client: unblind the issuer's signature into a token, and check it before using it. */
export function finalizeToken(pending: PendingToken, blindSignature: string): string {
  const { n, length } = publicParts(pending.issuer.publicKey);
  const signature = toBytes((toBig(fromB64u(blindSignature)) * BigInt(`0x${pending.inverse}`)) % n, length);
  const token = Buffer.concat([fromB64u(pending.input), signature]);
  verifyTokenSignature(pending.issuer, token);
  return b64u(token);
}

function verifyTokenSignature(issuer: IssuerKey, token: Buffer): void {
  const { key, length } = publicParts(issuer.publicKey);
  const input = token.subarray(0, 98);
  const authenticator = token.subarray(98);
  if (authenticator.length !== length) throw new TokenError('token has the wrong length');
  const ok = verify('sha384', input, { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: SALT_LEN }, authenticator);
  if (!ok) throw new TokenError('token signature is invalid');
}

/**
 * Origin: check a token is type 2, for this origin and an issuer it trusts, and validly signed. Returns
 * the nonce, which the origin must record so the token can't be spent twice.
 */
export function verifyToken(token: string, origin: string, trusted: IssuerKey[]): string {
  const bytes = fromB64u(token);
  if (bytes.readUInt16BE(0) !== TOKEN_TYPE) throw new TokenError('unsupported token type');
  const nonce = bytes.subarray(2, 34);
  const challengeDigest = bytes.subarray(34, 66);
  const keyId = bytes.subarray(66, 98);
  const issuer = trusted.find((candidate) => tokenKeyId(candidate.publicKey).equals(keyId));
  if (!issuer) throw new TokenError('token is from an issuer this server does not trust');
  if (!sha256(encodeChallenge(issuer.name, origin)).equals(challengeDigest)) throw new TokenError('token is for a different origin');
  verifyTokenSignature(issuer, bytes);
  return b64u(nonce);
}
