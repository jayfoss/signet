/**
 * Escalating a thread to a live A2A session (Agent2Agent protocol, JSON-RPC over HTTP).
 *
 * The offer travels inside the MLS thread as a signed `session.offer` intent, so only thread members
 * see the endpoint. Both sides derive the session's bearer token from the thread's MLS exporter secret
 * for the current epoch; nothing secret crosses the wire. Only current members can compute it, and a
 * rekey (say, after revoking an agent) changes the epoch and ends the session. The live exchange is for
 * fast back-and-forth: anything binding must come back to the thread as a signed message.
 */
import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { sha256 } from './crypto';
import { canonicalJson } from './encoding';

export const LIVE_LABEL = 'signet live v0';

/** A2A agent card (protocol 0.3), with Signet's bearer scheme. */
export interface AgentCard {
  name: string;
  description: string;
  url: string;
  version: string;
  protocolVersion: string;
  capabilities: Record<string, unknown>;
  defaultInputModes: string[];
  defaultOutputModes: string[];
  skills: { id: string; name: string; description: string; tags: string[] }[];
  securitySchemes: Record<string, { type: 'http'; scheme: 'bearer'; description?: string }>;
  security: Record<string, string[]>[];
}

export const agentCardHash = (card: AgentCard): string => sha256(canonicalJson(card));
export const newSessionId = (): string => `s_${randomBytes(12).toString('base64url')}`;

export interface LiveTurn {
  sessionId: string;
  thread: string;
  text: string;
}

/** Decides whether a bearer token is the current one for a session; returns its thread if so. */
export type LiveAuthorizer = (sessionId: string, token: string) => string | null;

export const tokensMatch = (a: string, b: string): boolean => {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
};

async function readJson(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    size += (chunk as Buffer).length;
    if (size > 1_000_000) throw new Error('body too large');
    chunks.push(chunk as Buffer);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

/**
 * A minimal A2A server for one Signet agent: serves its agent card and answers `message/send`, but only
 * for callers holding the current token of a session this agent offered.
 */
export class LiveGateway {
  private readonly http: Server;
  private publicUrl = '';

  constructor(
    private readonly describe: Omit<AgentCard, 'url' | 'securitySchemes' | 'security' | 'protocolVersion'>,
    private readonly authorize: LiveAuthorizer,
    private readonly handle: (turn: LiveTurn) => Promise<string> | string,
  ) {
    this.http = createServer((request, response) => void this.serve(request, response));
  }

  get url(): string {
    return this.publicUrl;
  }

  get card(): AgentCard {
    return {
      ...this.describe,
      url: this.publicUrl,
      protocolVersion: '0.3.0',
      securitySchemes: { signet: { type: 'http', scheme: 'bearer', description: 'Token derived from the Signet thread (MLS exporter)' } },
      security: [{ signet: [] }],
    };
  }

  async listen(port = 0, host = '127.0.0.1', publicUrl?: string): Promise<string> {
    await new Promise<void>((resolve) => this.http.listen(port, host, resolve));
    this.publicUrl = publicUrl ?? `http://${host}:${(this.http.address() as AddressInfo).port}`;
    return this.publicUrl;
  }

  close(): Promise<void> {
    return new Promise((resolve) => this.http.close(() => resolve()));
  }

  private async serve(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const reply = (status: number, body: unknown) => {
      response.writeHead(status, { 'content-type': 'application/json' });
      response.end(JSON.stringify(body));
    };
    if (request.method === 'GET' && request.url === '/.well-known/agent-card.json') return reply(200, this.card);
    if (request.method !== 'POST' || request.url !== '/') return reply(404, { error: 'not found' });
    const token = (request.headers.authorization ?? '').replace(/^Bearer /, '');
    let id: unknown = null;
    try {
      const rpc = (await readJson(request)) as {
        jsonrpc: string;
        id: unknown;
        method: string;
        params?: { message?: { parts?: { kind: string; text?: string }[]; metadata?: { sessionId?: string } } };
      };
      id = rpc.id ?? null;
      const sessionId = rpc.params?.message?.metadata?.sessionId ?? '';
      const thread = this.authorize(sessionId, token);
      if (!thread) return reply(401, { jsonrpc: '2.0', id, error: { code: -32001, message: 'not a current member of this session' } });
      if (rpc.method !== 'message/send') return reply(200, { jsonrpc: '2.0', id, error: { code: -32601, message: `unsupported method ${rpc.method}` } });
      const text = (rpc.params?.message?.parts ?? []).filter((part) => part.kind === 'text').map((part) => part.text ?? '').join('\n');
      const answer = await this.handle({ sessionId, thread, text });
      return reply(200, {
        jsonrpc: '2.0',
        id,
        result: { kind: 'message', role: 'agent', messageId: newSessionId(), parts: [{ kind: 'text', text: answer }], metadata: { sessionId } },
      });
    } catch (error) {
      return reply(200, { jsonrpc: '2.0', id, error: { code: -32603, message: error instanceof Error ? error.message : String(error) } });
    }
  }
}

/** The other side of a live session: an A2A client that authenticates with the thread-derived token. */
export class LiveSession {
  private next = 1;

  constructor(
    readonly url: string,
    readonly sessionId: string,
    private readonly token: string,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  async send(text: string): Promise<string> {
    const response = await this.fetchImpl(`${this.url}/`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${this.token}` },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: (this.next += 1),
        method: 'message/send',
        params: { message: { role: 'user', messageId: newSessionId(), parts: [{ kind: 'text', text }], metadata: { sessionId: this.sessionId } } },
      }),
    });
    const body = (await response.json()) as { result?: { parts?: { kind: string; text?: string }[] }; error?: { message: string } };
    if (!response.ok || body.error) throw new Error(`live session refused: ${response.status} ${body.error?.message ?? ''}`.trim());
    return (body.result?.parts ?? []).filter((part) => part.kind === 'text').map((part) => part.text ?? '').join('\n');
  }
}
