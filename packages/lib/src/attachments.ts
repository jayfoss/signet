import { decrypt, encrypt, randomSecret, sha256 } from './crypto';
import { b64u, fromB64u, utf8 } from './encoding';

export const MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024;

/**
 * Travels inside the encrypted message. The blob on the sender's server is ciphertext under a key that
 * exists only here, so the URL alone is useless.
 */
export interface AttachmentRef {
  name: string;
  type: string;
  size: number;
  url: string;
  key: string;
  iv: string;
  digest: string;
}

export interface FileInput {
  name: string;
  type: string;
  data: Uint8Array;
}

const AAD = utf8('signet0 attachment');

/** Encrypt a file under a fresh key. Upload `blob`, then complete the ref with the URL the server returns. */
export function sealAttachment(file: FileInput): { blob: Buffer; ref: Omit<AttachmentRef, 'url'> } {
  if (file.data.length > MAX_ATTACHMENT_BYTES) throw new Error(`${file.name} is over ${MAX_ATTACHMENT_BYTES} bytes`);
  const key = randomSecret();
  const { iv, ct } = encrypt(key, file.data, AAD);
  const blob = fromB64u(ct);
  return { blob, ref: { name: file.name, type: file.type, size: file.data.length, key: b64u(key), iv, digest: sha256(blob) } };
}

export function openAttachment(ref: AttachmentRef, blob: Uint8Array): Buffer {
  if (sha256(blob) !== ref.digest) throw new Error(`${ref.name} does not match its digest`);
  const data = decrypt(fromB64u(ref.key), { iv: ref.iv, ct: b64u(blob) }, AAD);
  if (data.length !== ref.size) throw new Error(`${ref.name} is the wrong size`);
  return data;
}
