export const b64u = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64url');
export const fromB64u = (text: string): Buffer => Buffer.from(text, 'base64url');
export const utf8 = (text: string): Buffer => Buffer.from(text, 'utf8');

/** JSON with object keys sorted, so every party signs and verifies the same bytes. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record)
    .filter((key) => record[key] !== undefined)
    .sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(',')}}`;
}
