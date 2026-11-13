import type { IncomingHttpHeaders, IncomingMessage, Server, ServerResponse } from 'node:http';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';

export class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
    /** Extra response headers, such as Signet-Primary on a 421. */
    readonly headers: Record<string, string> = {},
  ) {
    super(message);
  }
}

export interface HttpRequest {
  method: string;
  /** Path and query exactly as sent; this is what request signatures cover. */
  path: string;
  url: URL;
  headers: IncomingHttpHeaders;
  body: Buffer;
  remoteAddress: string;
}

/** A JSON body, or raw bytes with a content type. */
export type HttpResult = unknown | { raw: Buffer; contentType: string };

const isRaw = (result: unknown): result is { raw: Buffer; contentType: string } =>
  typeof result === 'object' && result !== null && Buffer.isBuffer((result as { raw?: unknown }).raw);

export const header = (headers: IncomingHttpHeaders, name: string): string => {
  const value = headers[name];
  if (typeof value !== 'string') throw new HttpError(401, `missing ${name} header`);
  return value;
};

export const json = <T>(request: HttpRequest): T => {
  try {
    return JSON.parse(request.body.toString('utf8')) as T;
  } catch {
    throw new HttpError(400, 'body is not JSON');
  }
};

async function readBody(request: IncomingMessage, limit: number): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    size += (chunk as Buffer).length;
    if (size > limit) throw new HttpError(413, 'body too large');
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
}

/** A tiny JSON-over-HTTP server with typed errors and a fixed body limit. */
export class JsonServer {
  readonly http: Server;
  private url = '';

  constructor(
    private readonly route: (request: HttpRequest) => Promise<HttpResult>,
    private readonly bodyLimit = 40 * 1024 * 1024,
    /** Headers added to every response, such as Signet-Term. */
    private readonly responseHeaders: () => Record<string, string> = () => ({}),
  ) {
    this.http = createServer((request, response) => void this.handle(request, response));
  }

  get publicUrl(): string {
    return this.url;
  }

  async listen(port = 0, host = '127.0.0.1', publicUrl?: string): Promise<string> {
    await new Promise<void>((resolve) => this.http.listen(port, host, resolve));
    const { port: bound } = this.http.address() as AddressInfo;
    this.url = publicUrl ?? `http://${host === '0.0.0.0' ? 'localhost' : host}:${bound}`;
    return this.url;
  }

  close(): Promise<void> {
    return new Promise((resolve, reject) => this.http.close((error) => (error ? reject(error) : resolve())));
  }

  private async handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    let status = 200;
    let result: HttpResult;
    let extra: Record<string, string> = {};
    try {
      const path = request.url ?? '/';
      result = await this.route({
        method: request.method ?? 'GET',
        path,
        url: new URL(path, 'http://signet.invalid'),
        headers: request.headers,
        body: await readBody(request, this.bodyLimit),
        remoteAddress: request.socket.remoteAddress ?? 'unknown',
      });
    } catch (error) {
      status = error instanceof HttpError ? error.status : 400;
      extra = error instanceof HttpError ? error.headers : {};
      result = { error: error instanceof Error ? error.message : String(error) };
    }
    const headers = { ...this.responseHeaders(), ...extra };
    if (isRaw(result)) {
      response.writeHead(status, { ...headers, 'content-type': result.contentType });
      response.end(result.raw);
      return;
    }
    response.writeHead(status, { ...headers, 'content-type': 'application/json' });
    response.end(JSON.stringify(result));
  }
}
