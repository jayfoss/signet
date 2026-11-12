/** Binary HTTP (RFC 9292), known-length form only: the inner message of an Oblivious HTTP request. */

export interface BinaryRequest {
  method: string;
  scheme: string;
  authority: string;
  path: string;
  headers: [string, string][];
  body: Uint8Array;
}

export interface BinaryResponse {
  status: number;
  headers: [string, string][];
  body: Uint8Array;
}

/** QUIC variable-length integer (RFC 9000 §16). */
function varint(value: number): Buffer {
  if (value < 0x40) return Buffer.from([value]);
  if (value < 0x4000) return Buffer.from([0x40 | (value >> 8), value & 0xff]);
  if (value < 0x40000000) {
    const out = Buffer.alloc(4);
    out.writeUInt32BE(value);
    out[0] |= 0x80;
    return out;
  }
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(BigInt(value));
  out[0] |= 0xc0;
  return out;
}

const withLength = (data: Uint8Array): Buffer => Buffer.concat([varint(data.length), data]);
const text = (value: string): Buffer => withLength(Buffer.from(value, 'utf8'));

function fields(headers: [string, string][]): Buffer {
  return withLength(Buffer.concat(headers.flatMap(([name, value]) => [text(name.toLowerCase()), text(value)])));
}

class Reader {
  private offset = 0;

  constructor(private readonly data: Buffer) {}

  varint(): number {
    if (this.offset >= this.data.length) throw new Error('truncated binary HTTP message');
    const first = this.data[this.offset];
    const length = 1 << (first >> 6);
    if (this.offset + length > this.data.length) throw new Error('truncated binary HTTP message');
    let value = BigInt(first & 0x3f);
    for (let i = 1; i < length; i += 1) value = (value << 8n) | BigInt(this.data[this.offset + i]);
    this.offset += length;
    return Number(value);
  }

  bytes(): Buffer {
    const length = this.varint();
    if (this.offset + length > this.data.length) throw new Error('truncated binary HTTP message');
    const out = this.data.subarray(this.offset, this.offset + length);
    this.offset += length;
    return out;
  }

  text(): string {
    return this.bytes().toString('utf8');
  }

  fields(): [string, string][] {
    const section = new Reader(this.bytes());
    const out: [string, string][] = [];
    while (!section.done) out.push([section.text(), section.text()]);
    return out;
  }

  get done(): boolean {
    return this.offset >= this.data.length;
  }
}

export function encodeRequest(request: BinaryRequest): Buffer {
  return Buffer.concat([
    varint(0),
    text(request.method),
    text(request.scheme),
    text(request.authority),
    text(request.path),
    fields(request.headers),
    withLength(request.body),
    varint(0),
  ]);
}

export function decodeRequest(data: Uint8Array): BinaryRequest {
  const reader = new Reader(Buffer.from(data));
  if (reader.varint() !== 0) throw new Error('expected a known-length binary HTTP request');
  return {
    method: reader.text(),
    scheme: reader.text(),
    authority: reader.text(),
    path: reader.text(),
    headers: reader.fields(),
    body: reader.done ? Buffer.alloc(0) : reader.bytes(),
  };
}

export function encodeResponse(response: BinaryResponse): Buffer {
  return Buffer.concat([varint(1), varint(response.status), fields(response.headers), withLength(response.body), varint(0)]);
}

export function decodeResponse(data: Uint8Array): BinaryResponse {
  const reader = new Reader(Buffer.from(data));
  if (reader.varint() !== 1) throw new Error('expected a known-length binary HTTP response');
  let status = reader.varint();
  // Skip informational (1xx) responses, each followed by its own field section.
  while (status >= 100 && status < 200) {
    reader.fields();
    status = reader.varint();
  }
  return { status, headers: reader.fields(), body: reader.done ? Buffer.alloc(0) : reader.bytes() };
}
