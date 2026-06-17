import { afterEach, describe, expect, it, vi } from 'vitest';

import worker, {
  deriveWebRTCStatus,
  normalizeCountryCode,
  parseTraceResponse,
  validateQueryTarget,
} from '../src/_worker.js';

async function runRequest(request) {
  return worker.fetch(request, {}, {});
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

  it('rejects placeholder query targets before hitting upstream', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const response = await runRequest(new Request('https://example.com/api/ipapi?q=-'));
    const body = await response.json();

    expect(response.status).toBe(400);
    expect(body.error).toBe('无效的 IP 地址或域名格式');
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('rejects malformed dotted-quad query targets before hitting upstream', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const badTargets = ['256.256.256.256', '1.1.1.999'];

    for (const target of badTargets) {
      const response = await runRequest(new Request(`https://example.com/api/ipapi?q=${encodeURIComponent(target)}`));
      const body = await response.json();

      expect(response.status).toBe(400);
      expect(body.error).toBe('无效的 IP 地址或域名格式');
    }

    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('rejects malformed IPv6 query targets before hitting upstream', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const badTargets = [':::::', '1:::8'];

    for (const target of badTargets) {
      const response = await runRequest(new Request(`https://example.com/api/ipapi?q=${encodeURIComponent(target)}`));
      const body = await response.json();

      expect(response.status).toBe(400);
      expect(body.error).toBe('无效的 IP 地址或域名格式');
    }

    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('accepts expanded IPv6 query targets', async () => {
    const target = '2001:0db8:0000:0000:0000:ff00:0042:8329';
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ ip: target }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );

    const response = await runRequest(new Request(`https://example.com/api/ipapi?q=${encodeURIComponent(target)}`));
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body.ip).toBe(target);
    expect(fetchSpy).toHaveBeenCalledWith(
      `https://api.ipapi.is?q=${encodeURIComponent(target)}`,
      expect.objectContaining({
        headers: { Accept: 'application/json' },
      })
    );
  });

  it('accepts compressed IPv6 targets with embedded IPv4 suffixes', async () => {
    const target = '2001:db8::192.0.2.33';
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ ip: target }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );

    const response = await runRequest(new Request(`https://example.com/api/ipapi?q=${encodeURIComponent(target)}`));
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body.ip).toBe(target);
    expect(fetchSpy).toHaveBeenCalledWith(
      `https://api.ipapi.is?q=${encodeURIComponent(target)}`,
      expect.objectContaining({
        headers: { Accept: 'application/json' },
      })
    );
  });
});

describe('helper logic', () => {
  it('validates only meaningful query targets', () => {
    expect(validateQueryTarget('1.1.1.1')).toBe(true);
    expect(validateQueryTarget('2001:db8::1')).toBe(true);
    expect(validateQueryTarget('2001:0db8:0000:0000:0000:ff00:0042:8329')).toBe(true);
    expect(validateQueryTarget('2001:db8::192.0.2.33')).toBe(true);
    expect(validateQueryTarget('2001:db8:3:4::192.0.2.33')).toBe(true);
    expect(validateQueryTarget('example.com')).toBe(true);

    expect(validateQueryTarget('-')).toBe(false);
    expect(validateQueryTarget('256.256.256.256')).toBe(false);
    expect(validateQueryTarget('1.1.1.999')).toBe(false);
    expect(validateQueryTarget(':::::')).toBe(false);
    expect(validateQueryTarget('1:::8')).toBe(false);
    expect(validateQueryTarget('加载失败')).toBe(false);
  });

  it('fails trace parsing when the response lacks a valid ip', () => {
    expect(parseTraceResponse('loc=US')).toEqual({ error: '响应中缺少有效 IP' });
    expect(parseTraceResponse('ip=-\nloc=US')).toEqual({ error: '响应中缺少有效 IP' });
  });

  it('parses valid trace responses into a usable result', () => {
    expect(parseTraceResponse('fl=29f\nip=1.1.1.1\nloc=us')).toEqual({
      ip: '1.1.1.1',
      countryCode: 'US',
      countryName: 'US',
      error: undefined,
    });

    expect(parseTraceResponse('ip=2001:0db8:0000:0000:0000:ff00:0042:8329\nloc=t1')).toEqual({
      ip: '2001:0db8:0000:0000:0000:ff00:0042:8329',
      countryCode: 'T1',
      countryName: 'T1',
      error: undefined,
    });
  });

  it('preserves pseudo-country codes returned by providers', () => {
    expect(normalizeCountryCode('t1')).toBe('T1');
    expect(normalizeCountryCode('A1')).toBe('A1');
    expect(normalizeCountryCode('us')).toBe('US');
    expect(normalizeCountryCode('usa')).toBe('');
  });

  it('derives neutral WebRTC statuses', () => {
    expect(deriveWebRTCStatus({ supported: true, ip: '1.1.1.1', error: null })).toEqual({
      status: 'safe',
      text: '已检测',
    });
    expect(deriveWebRTCStatus({ supported: false, ip: '-', error: '浏览器不支持 WebRTC' })).toEqual({
      status: 'unsupported',
      text: '不支持',
    });
    expect(deriveWebRTCStatus({ supported: true, ip: '-', error: '未检测到 IP' })).toEqual({
      status: 'unknown',
      text: '未检出',
    });
    expect(deriveWebRTCStatus({ supported: true, ip: '-', error: null })).toEqual({
      status: 'unknown',
      text: '无结果',
    });
  });
});

describe('rendered client script', () => {
  it('pins Babel standalone to a stable major version', async () => {
    const response = await runRequest(new Request('https://example.com/'));
    const html = await response.text();

    expect(html).toContain('https://unpkg.com/@babel/standalone@7.29.7/babel.min.js');
  });

  it('encodes ip when requesting /api/ipapi details', async () => {
    const response = await runRequest(new Request('https://example.com/'));
    const html = await response.text();

    expect(html).toContain('/api/ipapi?q=${encodeURIComponent(ip)}');
  });

  it('ships the new client-side guardrails and helper functions', async () => {
    const response = await runRequest(new Request('https://example.com/'));
    const html = await response.text();

    expect(html).toContain("const __name = (target, value) => {");
    expect(html).toContain('function parseTraceResponse');
    expect(html).toContain("const canViewDetails = !isLoading && !error && typeof onViewDetails === 'function' && isQueryableTarget(ip);");
    expect(html).toContain('if (!isQueryableTarget(ip)) return;');
    expect(html).toContain('WebRTC IP检测');
    expect(html).not.toContain('疑似泄漏');
    expect(html).not.toContain('一致性比对');
  });
});
