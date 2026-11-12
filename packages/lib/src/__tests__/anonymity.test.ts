import { decodeRequest, decodeResponse, encodeRequest, encodeResponse } from '../bhttp';
import {
  decapsulateRequest,
  decapsulateResponse,
  encapsulateRequest,
  encapsulateResponse,
  encodeKeyConfig,
  generateGatewayKey,
} from '../ohttp';
import { TokenError, blindSign, blindTokenRequest, finalizeToken, generateIssuerKey, verifyToken } from '../privacypass';

describe('binary HTTP', () => {
  it('round-trips a request and a response', () => {
    const request = { method: 'POST', scheme: 'https', authority: 'beta.test', path: '/v0/deliver-sealed', headers: [['content-type', 'application/json']] as [string, string][], body: Buffer.from('{"a":1}') };
    expect(decodeRequest(encodeRequest(request))).toEqual({ ...request, body: Buffer.from('{"a":1}') });
    const response = { status: 200, headers: [['content-type', 'application/json']] as [string, string][], body: Buffer.alloc(70_000, 7) };
    expect(decodeResponse(encodeResponse(response))).toEqual(response);
  });
});

describe('Oblivious HTTP', () => {
  it('lets only the gateway read the request, and only the sender read the response', async () => {
    const gateway = generateGatewayKey(7);
    const { message, pending } = await encapsulateRequest(encodeKeyConfig(gateway), Buffer.from('inner request'));
    expect(message.includes(Buffer.from('inner request'))).toBe(false);

    const opened = await decapsulateRequest(gateway, message);
    expect(opened.request.toString()).toBe('inner request');
    const reply = encapsulateResponse(opened.pending, Buffer.from('inner response'));
    expect(decapsulateResponse(pending, reply).toString()).toBe('inner response');

    await expect(decapsulateRequest(generateGatewayKey(7), message)).rejects.toThrow();
    expect(() => decapsulateResponse({ ...pending, secret: Buffer.alloc(16) }, reply)).toThrow();
  });
});

describe('Privacy Pass tokens', () => {
  const issuer = generateIssuerKey('issuer.test');
  const publicIssuer = { name: issuer.name, publicKey: issuer.publicKey };

  it('issues a token the issuer never sees, which only the intended origin accepts', () => {
    const pending = blindTokenRequest(publicIssuer, 'beta.test');
    const token = finalizeToken(pending, blindSign(issuer, pending.blinded));

    expect(Buffer.from(pending.blinded, 'base64url').equals(Buffer.from(token, 'base64url').subarray(98))).toBe(false);
    expect(verifyToken(token, 'beta.test', [publicIssuer])).toHaveLength(43);
    expect(() => verifyToken(token, 'gamma.test', [publicIssuer])).toThrow('different origin');
    const other = generateIssuerKey('issuer.test');
    expect(() => verifyToken(token, 'beta.test', [{ name: other.name, publicKey: other.publicKey }])).toThrow('does not trust');
  });

  it('rejects a tampered token and a signature for a different blinded message', () => {
    const pending = blindTokenRequest(publicIssuer, 'beta.test');
    const token = Buffer.from(finalizeToken(pending, blindSign(issuer, pending.blinded)), 'base64url');
    token[10] ^= 1;
    expect(() => verifyToken(token.toString('base64url'), 'beta.test', [publicIssuer])).toThrow(TokenError);

    const another = blindTokenRequest(publicIssuer, 'beta.test');
    expect(() => finalizeToken(pending, blindSign(issuer, another.blinded))).toThrow('invalid');
  });
});
