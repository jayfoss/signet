import type { KeyObject } from 'node:crypto';
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign,
  verify,
} from 'node:crypto';
import { Aes128Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from '@hpke/core';
import { b64u, canonicalJson, fromB64u, utf8 } from './encoding';

/** Raw 32-byte keys as base64url (the JWK `x` and `d` fields). */
export interface KeyPair {
  publicKey: string;
  privateKey: string;
}

export interface Ciphertext {
  iv: string;
  ct: string;
}

/** An HPKE (RFC 9180) base-mode ciphertext: the encapsulated key and the sealed bytes. */
export interface Sealed {
  enc: string;
  ct: string;
}

type Curve = 'Ed25519' | 'X25519';

function exportPair(privateKey: KeyObject): KeyPair {
  const jwk = privateKey.export({ format: 'jwk' });
  return { publicKey: jwk.x as string, privateKey: jwk.d as string };
}

const okpPrivate = (crv: Curve, key: KeyPair): KeyObject =>
  createPrivateKey({ key: { kty: 'OKP', crv, x: key.publicKey, d: key.privateKey }, format: 'jwk' });
const okpPublic = (crv: Curve, x: string): KeyObject =>
  createPublicKey({ key: { kty: 'OKP', crv, x }, format: 'jwk' });

export const generateSigningKey = (): KeyPair => exportPair(generateKeyPairSync('ed25519').privateKey);
export const generateAgreementKey = (): KeyPair => exportPair(generateKeyPairSync('x25519').privateKey);

export const signBytes = (key: KeyPair, data: Uint8Array): string =>
  b64u(sign(null, data, okpPrivate('Ed25519', key)));

export function verifyBytes(publicKey: string, data: Uint8Array, signature: string): boolean {
  try {
    return verify(null, data, okpPublic('Ed25519', publicKey), fromB64u(signature));
  } catch {
    return false;
  }
}

export const signJson = (key: KeyPair, value: unknown): string => signBytes(key, utf8(canonicalJson(value)));
export const verifyJson = (publicKey: string, value: unknown, signature: string): boolean =>
  verifyBytes(publicKey, utf8(canonicalJson(value)), signature);

/** AES-256-GCM with a random 96-bit nonce; the tag is appended to the ciphertext. */
export function encrypt(key: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Ciphertext {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  return { iv: b64u(iv), ct: b64u(ct) };
}

export function decrypt(key: Uint8Array, { iv, ct }: Ciphertext, aad: Uint8Array): Buffer {
  const raw = fromB64u(ct);
  const decipher = createDecipheriv('aes-256-gcm', key, fromB64u(iv));
  decipher.setAAD(aad);
  decipher.setAuthTag(raw.subarray(raw.length - 16));
  return Buffer.concat([decipher.update(raw.subarray(0, raw.length - 16)), decipher.final()]);
}

/** DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM: the same primitives as MLS cipher suite 1. */
const hpke = new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });

/** HPKE base-mode single-shot encryption to an X25519 public key. `info` binds the ciphertext to its purpose. */
/** Sealed payloads are padded to a multiple of this many bytes, so their size says little (Section 7.3). */
export const SEAL_PAD = 1024;

/** A 4-byte big-endian length, the payload, and zero bytes up to a multiple of `SEAL_PAD`. */
export function padPlaintext(plaintext: Uint8Array): Buffer {
  const total = Math.ceil((4 + plaintext.length) / SEAL_PAD) * SEAL_PAD;
  const padded = Buffer.alloc(total);
  padded.writeUInt32BE(plaintext.length, 0);
  Buffer.from(plaintext).copy(padded, 4);
  return padded;
}

/** Undo `padPlaintext`. Refuses a length larger than the plaintext, a wrong total size, or a non-zero padding byte. */
export function unpadPlaintext(padded: Uint8Array): Buffer {
  const buffer = Buffer.from(padded);
  if (buffer.length < SEAL_PAD || buffer.length % SEAL_PAD !== 0) throw new Error('sealed payload is not padded');
  const length = buffer.readUInt32BE(0);
  if (length > buffer.length - 4) throw new Error('sealed payload names a length larger than itself');
  if (buffer.subarray(4 + length).some((byte) => byte !== 0)) throw new Error('sealed payload has non-zero padding');
  return buffer.subarray(4, 4 + length);
}

export async function seal(recipient: string, plaintext: Uint8Array, info: string): Promise<Sealed> {
  const recipientPublicKey = await hpke.kem.importKey('jwk', { kty: 'OKP', crv: 'X25519', x: recipient }, true);
  const { enc, ct } = await hpke.seal({ recipientPublicKey, info: utf8(info) }, padPlaintext(plaintext));
  return { enc: b64u(new Uint8Array(enc)), ct: b64u(new Uint8Array(ct)) };
}

export async function open(mine: KeyPair, sealed: Sealed, info: string): Promise<Buffer> {
  const recipientKey = await hpke.kem.importKey(
    'jwk',
    { kty: 'OKP', crv: 'X25519', x: mine.publicKey, d: mine.privateKey },
    false,
  );
  const plaintext = await hpke.open({ recipientKey, enc: fromB64u(sealed.enc), info: utf8(info) }, fromB64u(sealed.ct));
  return unpadPlaintext(new Uint8Array(plaintext));
}

export const sha256 = (data: Uint8Array | string): string =>
  `sha256:${createHash('sha256').update(data).digest('base64url')}`;
export const sha256Bytes = (...parts: Uint8Array[]): Buffer => {
  const hash = createHash('sha256');
  for (const part of parts) hash.update(part);
  return hash.digest();
};
export const randomId = (prefix: string): string => `${prefix}_${randomBytes(12).toString('base64url')}`;
export const randomSecret = (): Buffer => randomBytes(32);
