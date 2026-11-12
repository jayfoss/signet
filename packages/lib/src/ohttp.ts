/**
 * Oblivious HTTP (RFC 9458). A sending server encapsulates a request to the receiving server's gateway
 * key and hands it to a relay. The relay sees who is sending but not the content or the inner request;
 * the gateway sees the content but only the relay's address. As long as relay and gateway don't
 * collude, the receiving server can't tell which server a sealed delivery came from.
 *
 * Suite: DHKEM(X25519, HKDF-SHA256) 0x0020, HKDF-SHA256 0x0001, AES-128-GCM 0x0001.
 */
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';
import { Aes128Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from '@hpke/core';
import type { KeyPair } from './crypto';
import { generateAgreementKey } from './crypto';
import { b64u, fromB64u } from './encoding';

export const OHTTP_REQUEST_TYPE = 'message/ohttp-req';
export const OHTTP_RESPONSE_TYPE = 'message/ohttp-res';
export const OHTTP_KEYS_TYPE = 'application/ohttp-keys';

const KEM_ID = 0x0020;
const KDF_ID = 0x0001;
const AEAD_ID = 0x0001;
const NK = 16;
const NN = 12;
const NENC = 32;

const suite = new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });

export interface GatewayKey {
  keyId: number;
  key: KeyPair;
}

export const generateGatewayKey = (keyId = 1): GatewayKey => ({ keyId, key: generateAgreementKey() });

/** RFC 9458 §3: one key configuration, length-prefixed as in application/ohttp-keys. */
export function encodeKeyConfig({ keyId, key }: GatewayKey): string {
  const config = Buffer.concat([
    Buffer.from([keyId]),
    u16(KEM_ID),
    fromB64u(key.publicKey),
    u16(4),
    u16(KDF_ID),
    u16(AEAD_ID),
  ]);
  return b64u(Buffer.concat([u16(config.length), config]));
}

export function decodeKeyConfig(data: string): { keyId: number; publicKey: string } {
  const bytes = fromB64u(data);
  const config = bytes.subarray(2, 2 + bytes.readUInt16BE(0));
  if (config.readUInt16BE(1) !== KEM_ID) throw new Error('unsupported OHTTP KEM');
  const publicKey = config.subarray(3, 3 + 32);
  const suitesLength = config.readUInt16BE(35);
  const suites = config.subarray(37, 37 + suitesLength);
  let supported = false;
  for (let i = 0; i + 4 <= suites.length; i += 4) supported ||= suites.readUInt16BE(i) === KDF_ID && suites.readUInt16BE(i + 2) === AEAD_ID;
  if (!supported) throw new Error('gateway offers no supported OHTTP cipher suite');
  return { keyId: config[0], publicKey: b64u(publicKey) };
}

function u16(value: number): Buffer {
  const out = Buffer.alloc(2);
  out.writeUInt16BE(value);
  return out;
}

const header = (keyId: number): Buffer => Buffer.concat([Buffer.from([keyId]), u16(KEM_ID), u16(KDF_ID), u16(AEAD_ID)]);
const requestInfo = (hdr: Buffer): Buffer => Buffer.concat([Buffer.from('message/bhttp request'), Buffer.from([0]), hdr]);
const RESPONSE_LABEL = Buffer.from('message/bhttp response');

function responseKeys(secret: Buffer, enc: Buffer, nonce: Buffer): { key: Buffer; iv: Buffer } {
  const salt = Buffer.concat([enc, nonce]);
  return {
    key: Buffer.from(hkdfSync('sha256', secret, salt, 'key', NK)),
    iv: Buffer.from(hkdfSync('sha256', secret, salt, 'nonce', NN)),
  };
}

/** What a sender keeps to read the response to an encapsulated request. */
export interface PendingResponse {
  enc: Buffer;
  secret: Buffer;
}

export async function encapsulateRequest(keyConfig: string, request: Uint8Array): Promise<{ message: Buffer; pending: PendingResponse }> {
  const { keyId, publicKey } = decodeKeyConfig(keyConfig);
  const hdr = header(keyId);
  const recipientPublicKey = await suite.kem.importKey('jwk', { kty: 'OKP', crv: 'X25519', x: publicKey }, true);
  const context = await suite.createSenderContext({ recipientPublicKey, info: requestInfo(hdr) });
  const ct = Buffer.from(await context.seal(request));
  const enc = Buffer.from(context.enc);
  const secret = Buffer.from(await context.export(RESPONSE_LABEL, Math.max(NN, NK)));
  return { message: Buffer.concat([hdr, enc, ct]), pending: { enc, secret } };
}

export async function decapsulateRequest(gateway: GatewayKey, message: Uint8Array): Promise<{ request: Buffer; pending: PendingResponse }> {
  const data = Buffer.from(message);
  const hdr = data.subarray(0, 7);
  if (hdr[0] !== gateway.keyId || hdr.readUInt16BE(1) !== KEM_ID || hdr.readUInt16BE(3) !== KDF_ID || hdr.readUInt16BE(5) !== AEAD_ID) {
    throw new Error('unknown OHTTP key or suite');
  }
  const enc = data.subarray(7, 7 + NENC);
  const recipientKey = await suite.kem.importKey(
    'jwk',
    { kty: 'OKP', crv: 'X25519', x: gateway.key.publicKey, d: gateway.key.privateKey },
    false,
  );
  const context = await suite.createRecipientContext({ recipientKey, enc, info: requestInfo(Buffer.from(hdr)) });
  const request = Buffer.from(await context.open(data.subarray(7 + NENC)));
  const secret = Buffer.from(await context.export(RESPONSE_LABEL, Math.max(NN, NK)));
  return { request, pending: { enc: Buffer.from(enc), secret } };
}

export function encapsulateResponse(pending: PendingResponse, response: Uint8Array): Buffer {
  const nonce = randomBytes(Math.max(NN, NK));
  const { key, iv } = responseKeys(pending.secret, pending.enc, nonce);
  const cipher = createCipheriv('aes-128-gcm', key, iv);
  return Buffer.concat([nonce, cipher.update(response), cipher.final(), cipher.getAuthTag()]);
}

export function decapsulateResponse(pending: PendingResponse, message: Uint8Array): Buffer {
  const data = Buffer.from(message);
  const nonceLength = Math.max(NN, NK);
  const { key, iv } = responseKeys(pending.secret, pending.enc, data.subarray(0, nonceLength));
  const decipher = createDecipheriv('aes-128-gcm', key, iv);
  decipher.setAuthTag(data.subarray(data.length - 16));
  return Buffer.concat([decipher.update(data.subarray(nonceLength, data.length - 16)), decipher.final()]);
}
