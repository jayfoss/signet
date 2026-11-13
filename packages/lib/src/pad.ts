/** Delivery envelopes are padded to a multiple of this many bytes (Section 10.2). */
export const ENVELOPE_PAD = 1024;

const PAD_MEMBER = ',"pad":""'.length;

/**
 * Serialize a JSON object with a trailing `pad` member of zeros, so the whole is a multiple of `block` bytes.
 * Receivers ignore `pad`. The envelope of a delivery carries ids, a kind and recipients around a payload that is
 * already padded; this makes its size, as seen by the servers and the network between them, depend on little.
 */
export function padJson(value: Record<string, unknown>, block = ENVELOPE_PAD): string {
  const json = JSON.stringify(value);
  const bytes = Buffer.byteLength(json);
  const total = Math.ceil((bytes + PAD_MEMBER) / block) * block;
  return `${json.slice(0, -1)},"pad":"${'0'.repeat(total - bytes - PAD_MEMBER)}"}`;
}
