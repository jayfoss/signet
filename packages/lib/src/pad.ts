/** Delivery envelopes are padded to a multiple of this many bytes (Section 10.2). */
export const ENVELOPE_PAD = 1024;

/** Deliveries to a domain that is sent cover are padded to this many bytes instead (Section 10.6.2). */
export const COVER_CELL = 4096;

const PAD_MEMBER = ',"pad":""'.length;

/**
 * Serialize a JSON object with a trailing `pad` member of zeros, so the whole is a multiple of `block` bytes.
 * Receivers ignore `pad`. The envelope of a delivery carries ids, a kind and recipients around a payload that is
 * already padded; this makes its size, as seen by the servers and the network between them, depend on little.
 */
export function padJson(value: Record<string, unknown>, block = ENVELOPE_PAD): string {
  const json = JSON.stringify(value);
  const bytes = Buffer.byteLength(json);
  // An empty object has no member to put a comma after.
  const lead = json === '{}' ? '{' : `${json.slice(0, -1)},`;
  const overhead = PAD_MEMBER - (json === '{}' ? 1 : 0);
  const total = Math.ceil((bytes + overhead) / block) * block;
  return `${lead}"pad":"${'0'.repeat(total - bytes - overhead)}"}`;
}

/**
 * Serialize a JSON object with a `pad` member of zeros so that the whole is exactly `total` bytes. Throws if the object
 * alone is longer. For a request whose size, headers and all, has to match another's (Section 10.6.2).
 */
export function padJsonTo(value: Record<string, unknown>, total: number): string {
  const json = JSON.stringify(value);
  const empty = json === '{}';
  const overhead = PAD_MEMBER - (empty ? 1 : 0);
  const fill = total - Buffer.byteLength(json) - overhead;
  if (fill < 0) throw new Error(`the object is ${Buffer.byteLength(json) + overhead} bytes with its pad, more than ${total}`);
  return `${empty ? '{' : `${json.slice(0, -1)},`}"pad":"${'0'.repeat(fill)}"}`;
}
