import { createExecutionContext, env, waitOnExecutionContext } from 'cloudflare:test';
import { afterEach, describe, expect, it, vi } from 'vitest';

import worker from '../src/_worker.js';

async function runRequest(request) {
  const ctx = createExecutionContext();
  const response = await worker.fetch(request, env, ctx);
  await waitOnExecutionContext(ctx);
  return response;
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('worker API hardening', () => {
  it('propagates upstream non-2xx status for /api/ipapi', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ error: 'upstream limited' }), {
        status: 429,
        headers: { 'content-type': 'application/json' },
      })
    );

    const response = await runRequest(new Request('https://example.com/api/ipapi?q=1.1.1.1'));
    const body = await response.json();

    expect(response.status).toBe(429);
    expect(body.error).toBe('upstream limited');
    expect(response.headers.get('access-control-allow-origin')).toBe('https://example.com');
  });

  it('returns 405 for non-GET /api/ipapi', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const response = await runRequest(new Request('https://example.com/api/ipapi?q=1.1.1.1', { method: 'POST' }));
    const body = await response.json();

    expect(response.status).toBe(405);
    expect(response.headers.get('allow')).toBe('GET, OPTIONS');
    expect(body.error).toBe('Method Not Allowed');
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('returns 405 for non-GET /api/cf-trace', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const response = await runRequest(new Request('https://example.com/api/cf-trace', { method: 'POST' }));

    expect(response.status).toBe(405);
    expect(response.headers.get('allow')).toBe('GET, OPTIONS');
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('falls back CORS allow-origin to self origin for cross-origin calls', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ ip: '1.1.1.1' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );

    const response = await runRequest(
      new Request('https://example.com/api/ipapi?q=1.1.1.1', {
        headers: { Origin: 'https://evil.example' },
      })
    );

    expect(response.headers.get('access-control-allow-origin')).toBe('https://example.com');
  });
});

describe('client script safety', () => {
  it('encodes ip when requesting /api/ipapi details', async () => {
    const response = await runRequest(new Request('https://example.com/'));
    const html = await response.text();

    expect(html).toContain('/api/ipapi?q=${encodeURIComponent(ip)}');
  });
});
