import { afterEach, describe, expect, it, vi } from 'vitest';
import { runInNewContext } from 'node:vm';

import worker, {
  deriveWebRTCStatus,
  normalizeCountryCode,
  parseTraceResponse,
  resetRuntimeCaches,
  validateQueryTarget,
} from '../src/_worker.js';

async function runRequest(request) {
  return worker.fetch(request, {}, {});
}

afterEach(() => {
  vi.restoreAllMocks();
  resetRuntimeCaches();
});

describe('worker API hardening', () => {
  it('propagates upstream non-2xx status for /api/ipapi', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(
      async () =>
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
    vi.spyOn(globalThis, 'fetch').mockImplementation(
      async () =>
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
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(
      async () =>
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
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(
      async () =>
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

describe('IP lookup fallback', () => {
  it('falls back to ipwho.is when ipapi.is is unavailable', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input);

      if (url.startsWith('https://api.ipapi.is')) {
        return new Response(JSON.stringify({ error: 'down' }), {
          status: 503,
          headers: { 'content-type': 'application/json' },
        });
      }

      if (url.startsWith('https://ipwho.is/')) {
        return new Response(
          JSON.stringify({
            success: true,
            ip: '1.1.1.1',
            country: 'Australia',
            country_code: 'AU',
            region: 'Queensland',
            city: 'Brisbane',
            postal: '4001',
            latitude: -27.4,
            longitude: 153.0,
            is_eu: false,
            connection: { asn: 13335, org: 'APNIC Research', isp: 'Cloudflare', domain: 'cloudflare.com' },
            timezone: { id: 'Australia/Brisbane' },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }

      if (url.startsWith('http://ip-api.com/')) {
        return new Response(
          JSON.stringify({
            status: 'success',
            query: '1.1.1.1',
            country: 'Australia',
            countryCode: 'AU',
            regionName: 'Queensland',
            city: 'Brisbane',
            lat: -27.4,
            lon: 153.0,
            timezone: 'Australia/Brisbane',
            isp: 'Cloudflare',
            org: 'APNIC Research',
            as: 'AS13335 Cloudflare, Inc.',
            asname: 'CLOUDFLARENET',
            mobile: false,
            proxy: true,
            hosting: false,
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }

      return new Response('{}', { status: 404 });
    });

    const response = await runRequest(new Request('https://example.com/api/ipapi?q=1.1.1.1'));
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body.ip).toBe('1.1.1.1');
    expect(body._source).toBe('ipwho.is + ip-api.com');
    expect(body.location.country_code).toBe('AU');
    expect(body.company.name).toBe('APNIC Research');
    expect(body.asn.asn).toBe('13335');
    expect(body.is_proxy).toBe(true);
    expect(body.is_datacenter).toBe(false);
  });

  it('falls back to ip-api.com when ipapi.is and ipwho.is both fail', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input);

      if (url.startsWith('http://ip-api.com/')) {
        return new Response(
          JSON.stringify({
            status: 'success',
            query: '8.8.8.8',
            country: 'United States',
            countryCode: 'US',
            regionName: 'California',
            city: 'Mountain View',
            lat: 37.4,
            lon: -122.1,
            timezone: 'America/Los_Angeles',
            isp: 'Google LLC',
            org: 'Google Public DNS',
            as: 'AS15169 Google LLC',
            asname: 'GOOGLE',
            mobile: false,
            proxy: false,
            hosting: true,
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }

      return new Response(JSON.stringify({ error: 'down' }), {
        status: 503,
        headers: { 'content-type': 'application/json' },
      });
    });

    const response = await runRequest(new Request('https://example.com/api/ipapi?q=8.8.8.8'));
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body._source).toBe('ip-api.com');
    expect(body.ip).toBe('8.8.8.8');
    expect(body.company.type).toBe('hosting');
    expect(body.is_datacenter).toBe(true);
  });

  it('uses the Net.Coffee trust score and risk flags as the reference source', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input);

      if (url.startsWith('https://ip.net.coffee/api/ip/lookup/')) {
        return new Response(
          JSON.stringify({
            ip: '8.8.8.8',
            trust_score: 63,
            company_name: 'Google LLC',
            isp: 'Google',
            company_type: 'hosting',
            asn: 15169,
            asname: 'GOOGLE',
            asOrganization: 'Google LLC',
            asn_kind: 'hosting',
            country: 'United States',
            countryCode: 'us',
            registered_country: 'United States',
            registered_country_code: 'us',
            cidr: '8.8.8.0/24',
            range: { first: '8.8.8.0', last: '8.8.8.255', count: 256 },
            rdns: 'dns.google',
            reddit_blocked: false,
            rpki_status: 'valid',
            asn_ipv4_count: 4078592,
            asn_allocated: '2000-03-30',
            asn_tbps: '100+Tbps',
            abuser_score: '',
            intelligence: { abuser_score_raw: '' },
            is_mobile: false,
            is_datacenter: true,
            is_crawler: false,
            is_proxy: false,
            is_vpn: false,
            is_tor: false,
            is_abuser: false,
            is_bogon: false,
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }

      if (url.startsWith('http://ip-api.com/')) {
        return new Response(
          JSON.stringify({
            status: 'success',
            query: '8.8.8.8',
            country: 'United States',
            countryCode: 'US',
            regionName: 'California',
            city: 'Mountain View',
            lat: 37.4,
            lon: -122.1,
            timezone: 'America/Los_Angeles',
            isp: 'Google LLC',
            org: 'Google Public DNS',
            as: 'AS15169 Google LLC',
            asname: 'GOOGLE',
            mobile: false,
            proxy: true,
            hosting: true,
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }

      return new Response(JSON.stringify({ error: 'down' }), {
        status: 503,
        headers: { 'content-type': 'application/json' },
      });
    });

    const response = await runRequest(new Request('https://example.com/api/ipapi?q=8.8.8.8'));
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body._source).toContain('Net.Coffee');
    expect(body.trust_score).toBe(63);
    expect(body.company.name).toBe('Google LLC');
    expect(body.company.isp).toBe('Google');
    expect(body.asn.name).toBe('GOOGLE');
    expect(body.asn.org).toBe('Google LLC');
    expect(body.asn_ipv4_count).toBe(4078592);
    expect(body.rpki_status).toBe('valid');
    expect(body.reddit_blocked).toBe(false);
    expect(body.ptr).toBe('dns.google');
    expect(body.is_proxy).toBe(false);
    expect(body.range).toEqual({ first: '8.8.8.0', last: '8.8.8.255', count: 256 });
  });

  it('merges RDAP RIR, network and abuse contact into the detail', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input);

      if (url.startsWith('https://rdap.arin.net/registry/ip/')) {
        return new Response(
          JSON.stringify({
            handle: 'NET-8-8-8-0-2',
            name: 'GOGL',
            startAddress: '8.8.8.0',
            endAddress: '8.8.8.255',
            cidr0_cidrs: [{ v4prefix: '8.8.8.0', length: 24 }],
            country: 'US',
            entities: [
              {
                handle: 'GOGL',
                roles: ['registrant'],
                vcardArray: ['vcard', [['fn', {}, 'text', 'Google LLC']]],
                entities: [
                  {
                    handle: 'ABUSE5250-ARIN',
                    roles: ['abuse'],
                    vcardArray: [
                      'vcard',
                      [
                        ['fn', {}, 'text', 'Abuse'],
                        ['email', {}, 'text', 'network-abuse@google.com'],
                        ['tel', {}, 'text', '+1-650-253-0000'],
                        [
                          'adr',
                          { label: '1600 Amphitheatre Parkway\nMountain View\nCA\n94043\nUnited States' },
                          'text',
                          ['', '', '', '', '', '', ''],
                        ],
                      ],
                    ],
                  },
                ],
              },
            ],
          }),
          { status: 200, headers: { 'content-type': 'application/rdap+json' } }
        );
      }

      if (url.startsWith('https://cloudflare-dns.com/dns-query')) {
        return new Response(
          JSON.stringify({ Status: 0, Answer: [{ name: '8.8.8.8.in-addr.arpa', type: 12, data: 'dns.google.' }] }),
          { status: 200, headers: { 'content-type': 'application/dns-json' } }
        );
      }

      if (url.startsWith('http://ip-api.com/')) {
        return new Response(
          JSON.stringify({
            status: 'success',
            query: '8.8.8.8',
            country: 'United States',
            countryCode: 'US',
            regionName: 'California',
            city: 'Mountain View',
            lat: 37.4,
            lon: -122.1,
            timezone: 'America/Los_Angeles',
            isp: 'Google LLC',
            org: 'Google Public DNS',
            as: 'AS15169 Google LLC',
            asname: 'GOOGLE',
            mobile: false,
            proxy: false,
            hosting: true,
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }

      return new Response(JSON.stringify({ error: 'down' }), {
        status: 503,
        headers: { 'content-type': 'application/json' },
      });
    });

    const response = await runRequest(new Request('https://example.com/api/ipapi?q=8.8.8.8'));
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body.rir).toBe('ARIN');
    expect(body.company.network).toBe('8.8.8.0/24');
    expect(body.asn.route).toBe('8.8.8.0/24');
    expect(body.abuse).toEqual({
      name: 'Abuse',
      email: 'network-abuse@google.com',
      phone: '+1-650-253-0000',
      address: '1600 Amphitheatre Parkway, Mountain View, CA, 94043, United States',
    });
    expect(body._source).toContain('RDAP');
    expect(body.asn.name).toBe('GOOGLE');
    expect(body.asn.org).toBe('Google Public DNS');
    expect(body.registered_country_code).toBe('US');
    expect(body.range).toEqual({ first: '8.8.8.0', last: '8.8.8.255', count: 256 });
    expect(body.ptr).toBe('dns.google');
  });

  it('adds StopForumSpam abuse reports and Tor exit membership', async () => {
    resetRuntimeCaches();

    const torList = [
      '9.9.9.9',
      ...Array.from({ length: 200 }, (_, index) => `10.0.${Math.floor(index / 256)}.${index % 256}`),
    ].join('\n');

    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input);

      if (url.startsWith('https://www.stopforumspam.com/api')) {
        return new Response(
          JSON.stringify({ success: 1, ip: { value: '9.9.9.9', frequency: 42, appears: 1 } }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }

      if (url.startsWith('https://check.torproject.org/torbulkexitlist')) {
        return new Response(torList, { status: 200, headers: { 'content-type': 'text/plain' } });
      }

      if (url.startsWith('http://ip-api.com/')) {
        return new Response(
          JSON.stringify({
            status: 'success',
            query: '9.9.9.9',
            country: 'United States',
            countryCode: 'US',
            regionName: 'California',
            city: 'Los Angeles',
            lat: 34,
            lon: -118,
            timezone: 'America/Los_Angeles',
            isp: 'Quad9',
            org: 'Quad9',
            as: 'AS19281 Quad9',
            asname: 'QUAD9',
            mobile: false,
            proxy: false,
            hosting: false,
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }

      return new Response(JSON.stringify({ error: 'down' }), {
        status: 503,
        headers: { 'content-type': 'application/json' },
      });
    });

    const response = await runRequest(new Request('https://example.com/api/ipapi?q=9.9.9.9'));
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body.is_abuser).toBe(true);
    expect(body.is_tor).toBe(true);
    expect(body.abuse.reports).toBe(42);
    expect(body._source).toBe('ip-api.com');
  });

  it('rejects a missing query target', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const response = await runRequest(new Request('https://example.com/api/ipapi'));
    const body = await response.json();

    expect(response.status).toBe(400);
    expect(body.error).toBe('缺少查询目标');
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('reuses the Tor list within an hour and refreshes membership after expiry', async () => {
    let now = 1000;
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    const filler = Array.from({ length: 100 }, (_, index) => `10.0.0.${index}`).join('\n');
    let torRequests = 0;
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input);
      if (url.startsWith('https://check.torproject.org/torbulkexitlist')) {
        torRequests += 1;
        return new Response(filler + (torRequests === 1 ? '\n9.9.9.9' : ''));
      }
      if (url.startsWith('http://ip-api.com/')) {
        return new Response(JSON.stringify({ status: 'success', query: '9.9.9.9' }));
      }
      return new Response('{}', { status: 503 });
    });
    const query = async () => (await runRequest(new Request('https://example.com/api/ipapi?q=9.9.9.9'))).json();

    expect((await query()).is_tor).toBe(true);
    now += 3600000 - 1;
    expect((await query()).is_tor).toBe(true);
    expect(torRequests).toBe(1);
    now += 1;
    const refreshed = await Promise.all([query(), query()]);
    expect(refreshed.map((detail) => detail.is_tor)).toEqual([false, false]);
    expect(torRequests).toBe(2);
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
  it.each([
    ['2001:0db8:0000:0000:0000:ff00:0042:8329', '2001:db8::ff00:42:8329', 63],
    ['2001:db8::ff00:42:8329', '2001:0db8:0000:0000:0000:ff00:0042:8329', 63],
    ['2001:db8::192.0.2.33', '2001:db8::c000:221', 63],
    ['2001:db8::1', '2001:db8::2', null],
  ])('only accepts a fallback score for the same IPv6 address (%s / %s)', async (ip, returnedIp, expectedScore) => {
    const html = await (await runRequest(new Request('https://example.com/'))).text();
    const sharedScript = html.match(/<script>([\s\S]*?)<\/script>/)[1];
    const addressHelpers = html.slice(html.indexOf('const canonicalizeIpAddress ='), html.indexOf('const lookupGeoByIpwho'));
    const fallbackEffect = html.match(/\/\/ Worker 端请求[\s\S]*?(useEffect\(\(\) => \{[\s\S]*?\}, \[isOpen, data\?\.ip, data\?\.trust_score\]\);)/)[1];
    const setScore = vi.fn();
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ ip: returnedIp, trust_score: 63 }))
    );
    let cleanup;
    runInNewContext(sharedScript + addressHelpers + fallbackEffect, {
      window: {}, tailwind: {}, URL, AbortController, fetch: fetchSpy,
      isOpen: true, data: { ip, trust_score: null }, setClientTrustScore: setScore,
      useEffect: (effect) => { cleanup = effect(); },
    });
    await new Promise((resolve) => setImmediate(resolve));

    expect(fetchSpy).toHaveBeenCalledOnce();
    if (expectedScore === null) expect(setScore).not.toHaveBeenCalled();
    else expect(setScore).toHaveBeenCalledWith(expectedScore);
    cleanup();
  });

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

  it('uses ipwho.is as the primary IP source and removes the retired proxies', async () => {
    const response = await runRequest(new Request('https://example.com/'));
    const html = await response.text();

    expect(html).toContain('https://ipwho.is/');
    expect(html).toContain("sourceName: 'ipwho.is'");
    expect(html).toContain('https://ipv4.icanhazip.com');
    expect(html).toContain('https://ipv6.myip.wtf/json');
    expect(html).toContain('https://v6.ident.me');
    expect(html).not.toContain('api.cmliussss.net');
    expect(html).not.toContain('api-ipv4.ip.sb');
    expect(html).not.toContain('api-ipv6.ip.sb');
    expect(html).not.toContain('api.ip.sb/geoip');
  });

  it('ships the new client-side guardrails and helper functions', async () => {
    const response = await runRequest(new Request('https://example.com/'));
    const html = await response.text();

    expect(html).toContain("const __name = (target, value) => {");
    expect(html).toContain('function parseTraceResponse');
    expect(html).toContain("const canViewDetails = !isLoading && !error && typeof onViewDetails === 'function' && isQueryableTarget(ip);");
    expect(html).toContain('if (!isQueryableTarget(ip)) return;');
    expect(html).toContain('WebRTC IP检测');
    expect(html).toContain('measureConnectivity');
    expect(html).toContain('const CONNECTIVITY_SAMPLE_COUNT = 10;');
    expect(html).toContain('connectivity-ms-value');
    expect(html).toContain('timeoutId = setTimeout(runRound, 1000);');
    expect(html).toContain('scheduleNextRound();');
    expect(html).toContain("name: '字节跳动'");
    expect(html).toContain("name: 'GitHub'");
    expect(html).toContain("name: 'YouTube'");
    expect(html).toContain("name: '微信'");
    expect(html).toContain("url: 'https://lf3-static.bytednsdoc.com/obj/eden-cn/uhbfnupkbps/toutiao_favicon.ico'");
    expect(html).toContain("url: 'https://github.github.io/janky/images/bg_hr.png'");
    expect(html).toContain("url: 'https://www.youtube.com/generate_204'");
    expect(html).toContain("url: 'https://res.wx.qq.com/a/wx_fed/assets/res/NTI4MWU5.ico'");
    expect(html).toContain("probe: 'image'");
    expect(html).toContain('cacheBust: true');
    expect(html).toContain('const loadImageWithTimeout = (url, timeout = 5000) => new Promise');
    expect(html).toContain("if (target.probe === 'image')");
    expect(html).toContain("nextUrl.searchParams.set('t', Date.now().toString())");
    expect(html).not.toContain('className="hero-panel mb-5');
    expect(html).not.toContain('timeout: 6000');
    expect(html).not.toContain('疑似泄漏');
    expect(html).not.toContain('一致性比对');
  });
});
