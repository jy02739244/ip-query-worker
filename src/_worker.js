// --- 安全辅助函数 ---

function normalizeTextValue(input) {
  if (typeof input === 'string') return input.trim();
  if (input === null || input === undefined) return '';
  return String(input).trim();
}

function isPlaceholderValue(input) {
  const value = normalizeTextValue(input);
  if (!value) return true;
  if (['-', '...', '未知', '加载中...', 'N/A'].includes(value)) return true;
  return value.includes('加载') || value.includes('失败');
}

function isValidIPv4Address(input) {
  const value = normalizeTextValue(input);
  const ipv4Regex = /^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$/;
  return ipv4Regex.test(value);
}

function isValidIPv6Address(input) {
  const value = normalizeTextValue(input);
  if (!value || !value.includes(':') || value.includes('[') || value.includes(']') || /\s/.test(value)) {
    return false;
  }

  if ((value.match(/::/g) || []).length > 1) return false;

  let address = value;
  let requiredSegmentCount = 8;

  if (value.includes('.')) {
    const ipv4Match = value.match(/^(.*?)(\d+\.\d+\.\d+\.\d+)$/);
    if (!ipv4Match) return false;

    const [, rawPrefix, ipv4Part] = ipv4Match;
    if (!isValidIPv4Address(ipv4Part)) return false;
    if (!rawPrefix.endsWith(':')) return false;

    address = rawPrefix.endsWith('::') ? rawPrefix : rawPrefix.slice(0, -1);
    requiredSegmentCount = 6;
  }

  const [head = '', tail = ''] = address.split('::');
  const parseSegments = (part) => {
    if (!part) return [];

    const segments = part.split(':');
    if (segments.some((segment) => !segment || !/^[0-9a-fA-F]{1,4}$/.test(segment))) {
      return null;
    }

    return segments;
  };

  const headSegments = parseSegments(head);
  const tailSegments = parseSegments(tail);

  if (!headSegments || !tailSegments) return false;

  const segmentCount = headSegments.length + tailSegments.length;
  if (value.includes('::')) return segmentCount < requiredSegmentCount;
  return segmentCount === requiredSegmentCount;
}

function isValidIpAddress(input) {
  return isValidIPv4Address(input) || isValidIPv6Address(input);
}

function isValidDomainName(input) {
  const value = normalizeTextValue(input);
  const labels = value.split('.');
  if (labels.length > 1 && labels.every((label) => /^\d+$/.test(label))) return false;
  const domainRegex = /^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))+$/;
  return domainRegex.test(value);
}

function isQueryableTarget(input) {
  const value = normalizeTextValue(input);
  if (isPlaceholderValue(value)) return false;
  return isValidIpAddress(value) || isValidDomainName(value);
}

function validateQueryTarget(input) {
  return isQueryableTarget(input);
}

function normalizeCountryCode(input) {
  const value = normalizeTextValue(input).toUpperCase();
  return /^[A-Z0-9]{2}$/.test(value) ? value : '';
}

function parseTraceResponse(text) {
  const raw = normalizeTextValue(text);
  const ip = normalizeTextValue(raw.match(/(?:^|\n)ip=([^\n]+)/)?.[1]);

  if (!isValidIpAddress(ip)) {
    return { error: '响应中缺少有效 IP' };
  }

  const countryCode = normalizeCountryCode(raw.match(/(?:^|\n)loc=([^\n]+)/)?.[1]);
  return {
    ip,
    countryCode,
    countryName: countryCode || '未知位置',
    error: undefined,
  };
}

function deriveWebRTCStatus(provider) {
  const detectedIp = normalizeTextValue(provider?.ip);

  if (!provider?.supported) return { status: 'unsupported', text: '不支持' };
  if (isValidIpAddress(detectedIp)) return { status: 'safe', text: '已检测' };
  if (provider?.error) return { status: 'unknown', text: '未检出' };
  return { status: 'unknown', text: '无结果' };
}

const CLIENT_SHARED_HELPERS = [
  normalizeTextValue,
  isPlaceholderValue,
  isValidIPv4Address,
  isValidIPv6Address,
  isValidIpAddress,
  isValidDomainName,
  isQueryableTarget,
  validateQueryTarget,
  normalizeCountryCode,
  parseTraceResponse,
  deriveWebRTCStatus,
].map((fn) => fn.toString()).join('\n');

export {
  validateQueryTarget,
  isQueryableTarget,
  parseTraceResponse,
  deriveWebRTCStatus,
  normalizeCountryCode,
};

// 转义 JSON 字符串以安全嵌入 <script> 标签（防止 XSS）
function safeJsonStringify(data) {
  return JSON.stringify(data)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/'/g, '\\u0027');

}

// 通用安全响应头
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
};

// CORS 相关头（限制为同源，避免被第三方站点滥用）
const CORS_BASE_HEADERS = {
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Max-Age': '86400',
  'Vary': 'Origin',
};

function getCorsHeaders(request) {
  const selfOrigin = new URL(request.url).origin;
  const requestOrigin = request.headers.get('Origin');
  const allowOrigin = requestOrigin && requestOrigin === selfOrigin ? requestOrigin : selfOrigin;

  return {
    ...CORS_BASE_HEADERS,
    'Access-Control-Allow-Origin': allowOrigin,
  };
}

// 32x32 PNG 格式图标（Google Favicon API 不支持 SVG，需要光栅格式）
// 使用懒加载缓存，避免每次请求都重复解码 base64
let _faviconPngCache = null;
function getFaviconPng() {
  if (!_faviconPngCache) {
    const pngBase64 = 'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAIAAAD8GO2jAAAAAXNSR0IArs4c6QAAAERlWElmTU0AKgAAAAgAAYdpAAQAAAABAAAAGgAAAAAAA6ABAAMAAAABAAEAAKACAAQAAAABAAAAIKADAAQAAAABAAAAIAAAAACshmLzAAAG90lEQVRIDT1Wa4hVVRjd+5xz79zHPLQcZzRRhzIMHQ2y8lFmqWmar0EKe0BQkNlYEvUjKBCDoECyGjUt6I9gRIiYWDhGpllZBoYamsY4maO9Zpx779zHeezTWt8+456Zc/b+9vrW99z7jB4cHPA8TykVY+Cl8YdF8qZAa8ixqTWE2qKUk0woE5EDGEHEQx0/UHM8lz/cIBOZscOBuZ0ItRXgSUWqK2Voj2ttDVsrometiHocGc9xnMgYgLXrmMhYNVqgPToEEoA50bGn6Y0Bhctth0JsxQYiLCUIBoCVEJnYeIAzCdAx1qi4L16Ko+IpZkqlXO04AMY6iqMIsBgPGdYBbeAoqGANUjGtteNhQR3aIJhYBi6KxPE37eEVX+wJ9u4ZAnBFR/3EthRAQQhVgrgNEhaGgSgDEhuE0qWhAgDcFnZYICeCd5TnOpCVy+bc2Vr3wcrRr2tilm7OnZdZ8GBu0uR0fR5BKROpCOmIYyQc2ki92AWVhoEi1aRcdEYW1Uo8WDC9Pf6Z0+GJ45Xei2F9vTv3/syylTm48vneypHDlVJJTWxz7rgzO3WaN358esRIJ5N1YISsQi/lQQTlorjPILCXSumffypve6/47z9hrerk8vGtk1Oz5mTunpVpHeNJ1enElT7/x+P+saPl8+fC8pCqy6gbR7nPb2iYMSPrB2xQxsH6a88mRzqFa9eJL18yl3qDRx/Pt0/LjJ/gNY920yknCOIwYHQ2kS0t6VUd6WUr8n//Ff7RG/1ysvLZ7tKlXnPXTK39JA9gMyaiAQhQBeri7ThGqXy9t3J1/eiWVFBDx6uqL1UXlNQISVYmYLGam72bxqVuvsU7sK+C/GvDbraFxMQBnZSFEoaELRNLmeJaNQ59yplWuA0/hJsYCJhPnB70pPZrMX6tjCDCaJs+a5wVnAOJm/xJvrDJE0cqg45jVoDEMorZgIA7rqqUzbXBQCFgdCcQGCSyT7ojDvMwWrHkFqaJFTQf0tfiuIggoMRzFXr3zU0D294toOmtRVJbkH2KHFsAJPJhO/ADhxp5onE8XVcxubTGqB2X56vrncGTJ/x75mVRNFJfV5YpfGfCRYklvQ4QX3AMMfhAKKC+eiUcGAhx4TIyBmw+2jF4qLu8dn3DffPqcGeQiiWQXCCxSUxkwUANJMvDLuCNOwsb0AAS0+1d11595b++Pr+uTqdctXtXcc+n5aeebljeUR+G7DqSizonYkiYUQNusJFESpDjYuna8mMHVyZ2H1nTMDCgN77W33e5dmB/6eMPhzpW5x97siGSY4FOBxCtyJ5IhpTXeuww10kRYT+KTBRFdXUKx8qvomlMFJrpt2c2vtFUGFQvb+jf1lWcvyD7zLpGuof2BSebOK6WI9+PsxlMRQhK+cVu0kWJddyDsRoz1kXafr8QOC7R6PH26dnXN40wkW5vT61/qdFzebXzHmcyNZqqpydAt48d54b8snCwMPRdyUlmTJIwpaMwntiWbml1v/2m/MD8nGBUrWamTMls2dqczapczo0ii6dXaKIwio8crrW2eBPa0thiEGBPDjQyLbWkOQj5tVKNTc7CxdkfvvNPna6m0olHYRiPGu3m8vj8kZcB4CWX45lT1e+PVRc+lGlqdNl9EpaoSVuTGMMKMDFxFKrFS3Mtrc6OrsFiIcShxSb4EBwOMrixpETFro5LxWjn9mJrq7NoSS4MxawcAXghlGhTNtdwWLSELOHu9dZ2Nl04b97fcg0ZcDz4QjyhMjBBJXAIAMCNvbazESoMjtVHtoVT0s4zyvSLRywbTSjfVzNnZ5/tbPyq29/8Vn95KEzVyaYAAE7X6XI52vz2tUMHa891NsycnQtwSye1ZIXEGTrFA2qXlIol6MMkOnVVRx5J2dlVuPJn/9r1TVOmptFdsI8vKfL+wdbC2V+DzpeblnfkAUb1eJ3Dhj1H5CC1LpUK9F8swkm5T7XBJQEEPvcpfezoED5w/f3R0mW5h1fm4Mb+vZUD+4ZG3uCue6Fxzr3ZAKnnzUIOe+nykgY7HY51cahAW1gyyRxJwiigR7ghrlwNPtlV6v6y7Hm82sLQLFyUXfNEQ+vYFM6XtCWVJRd4CBn6F1cX3MQ3GZ3DtNnSWBjgTGMidj2282/n/C/2l+HtkmX1k25Lx5HGd40RU9HmR7QYB2SkgDvy0ed9J5kTK8ORiHKSUGqibUQDhjWSTgIkQY4F2eg/IwaSJvEUThQ5yQ5EgqLAggiQXesS+lWF9rLlNQGUGJGnqID4uhwTEKE0+J8tMSsuECMRi0+wwPfwEK/EZTLDC2LtDHM4TU1J7bBtkHtBFHku/5WVjxjNknb4KTyMh3q4qfAvHKasCLjYaZAySsw1PtpY4gPE5BCtVBCF/wObUfxQ9HKafQAAAABJRU5ErkJggg==';
    _faviconPngCache = Uint8Array.from(atob(pngBase64), c => c.charCodeAt(0));
  }
  return _faviconPngCache;
}

// --- IP 数据源查询链 ---
// 参考 one-ip：先校验上游返回的 IP 与查询目标一致，再采用结果。
const IP_LOOKUP_TIMEOUT_MS = 6000;
const IP_API_COM_FIELDS = 'status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query';

async function fetchJsonWithTimeout(url, timeout = IP_LOOKUP_TIMEOUT_MS) {
  const response = await fetch(url, {
    headers: { Accept: 'application/json' },
    signal: AbortSignal.timeout(timeout),
  });

  if (!response.ok) {
    const error = new Error(`上游服务返回错误: HTTP ${response.status}`);
    error.status = response.status;
    error.body = await response.json().catch(() => null);
    throw error;
  }

  return await response.json();
}

function canonicalizeIpAddress(input) {
  const value = normalizeTextValue(input);
  if (isValidIPv4Address(value)) return value;
  if (!isValidIPv6Address(value)) return '';

  try {
    return new URL(`http://[${value}]/`).hostname.slice(1, -1);
  } catch (error) {
    return value.toLowerCase();
  }
}

function isSameIpAddress(left, right) {
  const leftValue = canonicalizeIpAddress(left);
  const rightValue = canonicalizeIpAddress(right);
  return Boolean(leftValue) && leftValue === rightValue;
}

function matchesLookupTarget(data, target) {
  const value = normalizeTextValue(data?.ip ?? data?.query);
  if (!isValidIpAddress(value)) return false;
  return isValidIpAddress(target) ? isSameIpAddress(value, target) : true;
}

function parseAsnNumber(value) {
  const match = normalizeTextValue(value).match(/^AS(\d+)/i);
  return match ? match[1] : '';
}

const EU_COUNTRY_CODES = new Set([
  'AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR',
  'HU', 'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 'RO', 'SK',
  'SI', 'ES', 'SE',
]);

function formatLocalTime(timezone) {
  if (!timezone) return '';
  try {
    return new Intl.DateTimeFormat('sv-SE', {
      timeZone: timezone,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    }).format(new Date());
  } catch (error) {
    return '';
  }
}

function normalizeScore(value) {
  if (value === null || value === undefined) return null;
  const text = typeof value === 'string' ? value.trim() : value;
  if (text === '') return null;

  const number = typeof text === 'number' ? text : Number(text);
  if (!Number.isFinite(number)) return null;

  return Math.max(0, Math.min(100, Math.round(number)));
}

function normalizeNetCoffeeRange(range) {
  if (!range || typeof range !== 'object') return null;

  const first = normalizeTextValue(range.first);
  const last = normalizeTextValue(range.last);
  if (first && last) {
    const computed = getRdapAddressRange({ startAddress: first, endAddress: last });
    if (computed) return computed;
  }

  const count = typeof range.count === 'number' ? range.count : normalizeTextValue(range.count);
  if (first || last || count !== '') return { first, last, count };
  return null;
}

function buildIpDetail(payload) {
  const countryCode = normalizeCountryCode(payload.countryCode);
  const detail = {
    ip: payload.ip,
    rir: payload.rir || '',
    company: {
      name: payload.companyName || payload.isp || payload.org || '',
      isp: payload.isp || payload.companyName || payload.org || '',
      domain: payload.domain || '',
      type: payload.companyType || (payload.hosting === true ? 'hosting' : ''),
      network: '',
      abuser_score: payload.companyScore || '',
    },
    asn: {
      asn: payload.asn || '',
      name: payload.asnName || '',
      org: payload.asnOrg || payload.org || '',
      route: '',
      type: payload.asnType || (payload.hosting === true ? 'hosting' : ''),
      country: countryCode,
      abuser_score: payload.asnScore || '',
    },
    location: {
      country: payload.country || '',
      country_code: countryCode,
      is_eu_member: typeof payload.isEu === 'boolean' ? payload.isEu : EU_COUNTRY_CODES.has(countryCode),
      state: payload.region || '',
      city: payload.city || '',
      zip: payload.zip || '',
      latitude: payload.latitude,
      longitude: payload.longitude,
      timezone: payload.timezone || '',
      local_time: payload.localTime || formatLocalTime(payload.timezone),
    },
    registered_country: payload.registeredCountry || '',
    registered_country_code: normalizeCountryCode(payload.registeredCountryCode),
    range: payload.range || null,
    ptr: payload.ptr || '',
    trust_score: normalizeScore(payload.trustScore),
    abuse_score: payload.abuseScore || '',
    datacenter_name: payload.datacenterName || '',
    rpki_status: payload.rpkiStatus || '',
    asn_ipv4_count: payload.asnIpv4Count ?? '',
    asn_allocated: payload.asnAllocated || '',
    asn_tbps: payload.asnTbps || '',
    abuse: null,
    _source: payload.source,
  };

  if (typeof payload.redditBlocked === 'boolean') detail.reddit_blocked = payload.redditBlocked;

  ['is_mobile', 'is_datacenter', 'is_satellite', 'is_crawler', 'is_proxy', 'is_vpn', 'is_tor', 'is_abuser', 'is_bogon'].forEach((key) => {
    if (typeof payload[key] === 'boolean') detail[key] = payload[key];
  });

  return detail;
}

async function lookupWithIpApiIs(target) {
  const data = await fetchJsonWithTimeout(`https://api.ipapi.is?q=${encodeURIComponent(target)}`);
  if (!matchesLookupTarget(data, target)) throw new Error('ipapi.is 未返回有效结果');

  const company = data.company && typeof data.company === 'object' ? data.company : null;
  const asn = data.asn && typeof data.asn === 'object' ? data.asn : null;
  const location = data.location || {};

  return buildIpDetail({
    ip: normalizeTextValue(data.ip),
    companyName: company?.name || (typeof data.company === 'string' ? data.company : ''),
    isp: company?.name || (typeof data.company === 'string' ? data.company : ''),
    domain: company?.domain,
    asn: asn?.asn || parseAsnNumber(data.asn),
    asnName: asn?.name || asn?.asname || '',
    asnOrg: asn?.org || normalizeTextValue(typeof data.asn === 'string' ? data.asn.replace(/^AS\d+\s*/i, '') : ''),
    country: location.country || data.country,
    countryCode: location.country_code || data.country_code,
    region: location.state || data.region,
    city: location.city || data.city,
    zip: location.zip,
    latitude: location.latitude ?? data.lat,
    longitude: location.longitude ?? data.lon,
    timezone: location.timezone || data.timezone,
    localTime: location.local_time,
    companyScore: company?.abuser_score,
    asnScore: asn?.abuser_score,
    isEu: location.is_eu_member,
    is_mobile: data.is_mobile,
    is_datacenter: data.is_datacenter,
    is_satellite: data.is_satellite,
    is_crawler: data.is_crawler,
    is_proxy: data.is_proxy,
    is_vpn: data.is_vpn,
    is_tor: data.is_tor,
    is_abuser: data.is_abuser,
    is_bogon: data.is_bogon,
    source: 'ipapi.is',
  });
}

async function lookupWithIpwho(target) {
  const data = await fetchJsonWithTimeout(`https://ipwho.is/${encodeURIComponent(target)}`);
  if (data?.success !== true || !matchesLookupTarget(data, target)) throw new Error('ipwho.is 未返回有效结果');

  const connection = data.connection || {};
  const timezone = data.timezone || {};

  return buildIpDetail({
    ip: normalizeTextValue(data.ip),
    companyName: connection.org || connection.isp,
    isp: connection.isp || connection.org,
    domain: connection.domain,
    asn: connection.asn ? String(connection.asn) : '',
    asnOrg: connection.org || connection.isp || '',
    country: data.country,
    countryCode: data.country_code,
    region: data.region,
    city: data.city,
    zip: data.postal,
    latitude: data.latitude,
    longitude: data.longitude,
    timezone: timezone.id,
    localTime: timezone.current_time,
    isEu: data.is_eu,
    is_bogon: false,
    source: 'ipwho.is',
  });
}

async function lookupWithIpApiCom(target) {
  const data = await fetchJsonWithTimeout(
    `http://ip-api.com/json/${encodeURIComponent(target)}?fields=${IP_API_COM_FIELDS}`,
    5000
  );
  if (data?.status !== 'success' || !matchesLookupTarget(data, target)) throw new Error('ip-api.com 未返回有效结果');

  return buildIpDetail({
    ip: normalizeTextValue(data.query),
    companyName: data.isp || data.org,
    isp: data.isp || data.org,
    asn: parseAsnNumber(data.as),
    asnName: data.asname || '',
    asnOrg: data.org || data.asname || data.isp,
    country: data.country,
    countryCode: data.countryCode,
    region: data.regionName,
    city: data.city,
    zip: data.zip,
    latitude: data.lat,
    longitude: data.lon,
    timezone: data.timezone,
    is_mobile: data.mobile,
    is_proxy: data.proxy,
    is_datacenter: data.hosting,
    hosting: data.hosting,
    is_bogon: false,
    source: 'ip-api.com',
  });
}

async function lookupWithNetCoffee(target) {
  if (!isValidIpAddress(target)) return null;

  // 参考项目 one-ip 的详情页直接展示 Net.Coffee 的 trust_score；
  // 这里把同一数据源作为首选，避免本地启发式评分与参考项目产生偏差。
  const data = await fetchJsonWithTimeout(
    `https://ip.net.coffee/api/ip/lookup/${encodeURIComponent(target)}`,
    5000
  );
  if (!matchesLookupTarget(data, target)) throw new Error('Net.Coffee 未返回有效结果');

  const detail = buildIpDetail({
    ip: normalizeTextValue(data.ip),
    companyName: data.company_name || data.isp,
    isp: data.isp || data.company_name,
    companyType: data.company_type,
    asn: data.asn ? String(data.asn) : '',
    asnName: data.asname || '',
    asnOrg: data.asOrganization || data.isp || data.company_name || '',
    asnType: data.asn_kind || data.company_type || '',
    country: data.country,
    countryCode: data.countryCode || data.country_code,
    region: data.region,
    city: data.city,
    latitude: data.latitude ?? data.lat,
    longitude: data.longitude ?? data.lon,
    timezone: data.timezone,
    registeredCountry: data.registered_country,
    registeredCountryCode: data.registered_country_code,
    trustScore: data.trust_score,
    abuseScore: data.intelligence?.abuser_score_raw ?? data.abuser_score,
    datacenterName: data.datacenter_name,
    rpkiStatus: data.rpki_status,
    asnIpv4Count: data.asn_ipv4_count,
    asnAllocated: data.asn_allocated,
    asnTbps: data.asn_tbps,
    redditBlocked: data.reddit_blocked,
    ptr: data.rdns,
    range: normalizeNetCoffeeRange(data.range),
    is_mobile: data.is_mobile,
    is_datacenter: data.is_datacenter,
    is_crawler: data.is_crawler,
    is_proxy: data.is_proxy,
    is_vpn: data.is_vpn,
    is_tor: data.is_tor,
    is_abuser: data.is_abuser,
    is_bogon: data.is_bogon,
    source: 'Net.Coffee',
  });

  detail.company.network = normalizeTextValue(data.cidr);
  detail.asn.route = normalizeTextValue(data.cidr);

  return detail;
}

function getRirFromRdapUrl(url) {
  let host = '';
  try {
    host = new URL(url).hostname.toLowerCase();
  } catch (error) {
    return '';
  }

  if (host.includes('apnic')) return 'APNIC';
  if (host.includes('ripe')) return 'RIPE NCC';
  if (host.includes('arin')) return 'ARIN';
  if (host.includes('lacnic')) return 'LACNIC';
  if (host.includes('afrinic')) return 'AFRINIC';
  if (host.includes('iana')) return 'IANA';
  return '';
}

function readVcardValue(property) {
  const value = property?.[3];
  if (Array.isArray(value)) return value.filter(Boolean).join(', ');
  return normalizeTextValue(value);
}

function extractVcardContact(entity) {
  const properties = entity?.vcardArray?.[1] || [];
  const findProperty = (name) => properties.find((item) => Array.isArray(item) && item[0] === name);
  const addressProperty = findProperty('adr');
  const addressParts = Array.isArray(addressProperty?.[3]) ? addressProperty[3].filter(Boolean) : [];
  const address = normalizeTextValue(addressProperty?.[1]?.label) || addressParts.join(', ');

  return {
    name: readVcardValue(findProperty('fn')) || normalizeTextValue(entity?.handle),
    email: readVcardValue(findProperty('email')),
    phone: readVcardValue(findProperty('tel')),
    address: address.replace(/\s*\n\s*/g, ', '),
  };
}

function collectRdapContacts(entities, output = []) {
  for (const entity of entities || []) {
    const contact = extractVcardContact(entity);
    contact.isAbuse = (entity?.roles || []).includes('abuse');
    if (contact.name || contact.email || contact.phone || contact.address) output.push(contact);
    collectRdapContacts(entity?.entities, output);
  }
  return output;
}

function findRdapAbuseContact(entities) {
  const contacts = collectRdapContacts(entities);
  const contact =
    contacts.find((item) => item.isAbuse && (item.email || item.name)) ||
    contacts.find((item) => item.email && item.email.toLowerCase().includes('abuse'));

  if (!contact) return null;
  return {
    name: contact.name,
    email: contact.email,
    phone: contact.phone,
    address: contact.address,
  };
}

function getRdapNetworkRange(data) {
  const cidr = (data?.cidr0_cidrs || [])[0];
  const prefix = cidr?.v4prefix || cidr?.v6prefix;
  if (prefix && cidr.length) return `${prefix}/${cidr.length}`;
  if (data?.startAddress && data?.endAddress) return `${data.startAddress} - ${data.endAddress}`;
  return '';
}

function ipv4ToNumber(value) {
  return value.split('.').reduce((total, part) => total * 256 + Number(part), 0);
}

function ipv6ToBigInt(value) {
  let input = value;
  const ipv4Match = input.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (ipv4Match) {
    const octets = ipv4Match[1].split('.').map(Number);
    const high = ((octets[0] << 8) | octets[1]).toString(16);
    const low = ((octets[2] << 8) | octets[3]).toString(16);
    input = `${input.slice(0, -ipv4Match[1].length)}${high}:${low}`;
  }

  const [head, tail] = input.split('::');
  const headParts = head ? head.split(':').filter(Boolean) : [];
  const tailParts = tail ? tail.split(':').filter(Boolean) : [];
  const missing = 8 - headParts.length - tailParts.length;
  const parts = [...headParts, ...Array(Math.max(0, missing)).fill('0'), ...tailParts];
  return parts.reduce((total, part) => (total << 16n) + BigInt(parseInt(part, 16)), 0n);
}

function getRdapAddressRange(data) {
  const first = normalizeTextValue(data?.startAddress);
  const last = normalizeTextValue(data?.endAddress);
  const cidr = (data?.cidr0_cidrs || [])[0];

  if (first && last && isValidIPv4Address(first) && isValidIPv4Address(last)) {
    return { first, last, count: ipv4ToNumber(last) - ipv4ToNumber(first) + 1 };
  }

  if (first && last && isValidIPv6Address(first) && isValidIPv6Address(last)) {
    const count = ipv6ToBigInt(last) - ipv6ToBigInt(first) + 1n;
    return {
      first,
      last,
      count: count <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(count) : count.toString(),
    };
  }

  const prefix = cidr?.v4prefix || cidr?.v6prefix;
  if (prefix && cidr?.length) {
    const bits = cidr.v6prefix ? 128 : 32;
    const count = 1n << BigInt(Math.max(0, bits - Number(cidr.length)));
    return {
      first: prefix,
      last: '',
      count: count <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(count) : count.toString(),
    };
  }

  return null;
}

async function lookupWithRdap(target) {
  if (!isValidIpAddress(target)) return null;

  // ARIN 的 RDAP 入口会对非 ARIN 地址返回 303，并跳转到对应 RIR
  const rdapUrl = `https://rdap.arin.net/registry/ip/${target}`;
  const response = await fetch(rdapUrl, {
    headers: { Accept: 'application/rdap+json, application/json' },
    redirect: 'follow',
    signal: AbortSignal.timeout(5000),
  });

  if (!response.ok) return null;
  const data = await response.json().catch(() => null);
  if (!data) return null;

  return {
    rir: getRirFromRdapUrl(response.url || rdapUrl),
    network: getRdapNetworkRange(data),
    networkName: normalizeTextValue(data.name) || normalizeTextValue(data.handle),
    countryCode: normalizeTextValue(data.country),
    range: getRdapAddressRange(data),
    abuse: findRdapAbuseContact(data.entities),
  };
}

function buildRdapDetail(target, rdap) {
  if (!rdap) return null;

  const detail = buildIpDetail({ ip: target, source: 'RDAP' });
  detail.rir = rdap.rir;
  detail.company.name = rdap.networkName;
  detail.company.network = rdap.network;
  detail.asn.route = rdap.network;
  detail.asn.country = rdap.countryCode;
  detail.location.country_code = rdap.countryCode;
  detail.registered_country_code = rdap.countryCode;
  detail.registered_country = rdap.countryCode;
  detail.range = rdap.range;
  detail.abuse = rdap.abuse;
  return detail;
}

async function lookupWithPtr(target) {
  if (!isValidIpAddress(target)) return null;

  const reverseName = isValidIPv4Address(target)
    ? `${target.split('.').reverse().join('.')}.in-addr.arpa`
    : `${ipv6ToBigInt(target).toString(16).padStart(32, '0').split('').reverse().join('.')}.ip6.arpa`;

  const urls = [
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(reverseName)}&type=PTR`,
    `https://dns.google/resolve?name=${encodeURIComponent(reverseName)}&type=PTR`,
  ];

  for (const url of urls) {
    try {
      const response = await fetch(url, {
        headers: { Accept: 'application/dns-json' },
        signal: AbortSignal.timeout(1500),
      });
      if (!response.ok) continue;

      const data = await response.json().catch(() => null);
      const answer = Array.isArray(data?.Answer)
        ? data.Answer.find((item) => item?.type === 12 && typeof item.data === 'string')
        : null;
      if (answer) return normalizeTextValue(answer.data.replace(/\.$/, ''));
    } catch (error) {
      // 尝试下一个 DoH 解析器
    }
  }

  return null;
}

const DETAIL_FLAG_KEYS = [
  'is_mobile',
  'is_datacenter',
  'is_satellite',
  'is_crawler',
  'is_proxy',
  'is_vpn',
  'is_tor',
  'is_abuser',
  'is_bogon',
];

function mergeDetail(base, extra) {
  if (!base || !extra) return base;

  const fill = (target, source, keys) => {
    for (const key of keys) {
      const value = source[key];
      if (
        (target[key] === undefined || target[key] === null || target[key] === '') &&
        value !== undefined &&
        value !== null &&
        value !== ''
      ) {
        target[key] = value;
      }
    }
  };

  fill(base, extra, [
    'rir',
    'registered_country',
    'registered_country_code',
    'range',
    'ptr',
    'trust_score',
    'abuse_score',
    'datacenter_name',
    'rpki_status',
    'asn_ipv4_count',
    'asn_allocated',
    'asn_tbps',
    'reddit_blocked',
  ]);
  fill(base.company, extra.company, ['name', 'isp', 'domain', 'type', 'network', 'abuser_score']);
  fill(base.asn, extra.asn, ['asn', 'name', 'org', 'route', 'type', 'country', 'abuser_score']);
  fill(base.location, extra.location, ['country', 'country_code', 'state', 'city', 'zip', 'latitude', 'longitude', 'timezone', 'local_time']);

  for (const key of DETAIL_FLAG_KEYS) {
    if (typeof extra[key] === 'boolean' && (base[key] === undefined || base[key] === null)) {
      base[key] = extra[key];
    }
  }

  if (!base.abuse && extra.abuse) base.abuse = extra.abuse;

  if (extra._source) {
    const sources = new Set(String(base._source || '').split(' + ').filter(Boolean));
    for (const source of String(extra._source).split(' + ').filter(Boolean)) sources.add(source);
    base._source = Array.from(sources).join(' + ');
  }

  return base;
}

function finalizeDetail(detail) {
  if (!detail) return detail;

  const countryCode = detail.location?.country_code || '';
  if (EU_COUNTRY_CODES.has(countryCode)) detail.location.is_eu_member = true;
  if (!detail.location.local_time) detail.location.local_time = formatLocalTime(detail.location.timezone);
  if (!detail.asn.country && countryCode) detail.asn.country = countryCode;
  if (!detail.company.isp && detail.company.name) detail.company.isp = detail.company.name;
  if (!detail.company.name && detail.asn.org) detail.company.name = detail.asn.org;

  return detail;
}

async function lookupWithStopForumSpam(target) {
  if (!isValidIpAddress(target)) return null;

  const data = await fetchJsonWithTimeout(
    `https://www.stopforumspam.com/api?ip=${encodeURIComponent(target)}&json`,
    2500
  );
  if (data?.success !== 1 || !data.ip) return null;

  return {
    is_abuser: Number(data.ip.appears) === 1,
    reports: Number(data.ip.frequency) || 0,
  };
}

const TOR_EXIT_LIST_TTL_MS = 3600000;
let torExitListPromise = null;
let torExitListExpiresAt = 0;
let torExitListRetryAt = 0;

function getTorExitList() {
  if (Date.now() < torExitListRetryAt) return Promise.resolve(null);

  if (!torExitListPromise || (torExitListExpiresAt > 0 && Date.now() >= torExitListExpiresAt)) {
    torExitListExpiresAt = 0;
    torExitListPromise = fetch('https://check.torproject.org/torbulkexitlist', {
      cf: { cacheTtl: TOR_EXIT_LIST_TTL_MS / 1000, cacheEverything: true },
      signal: AbortSignal.timeout(2500),
    })
      .then((response) => {
        if (!response.ok) throw new Error('Tor exit list unavailable');
        return response.text();
      })
      .then((text) => {
        const entries = text.split(/\s+/).filter((value) => isValidIPv4Address(value));
        if (entries.length < 100) throw new Error('Tor exit list incomplete');
        torExitListExpiresAt = Date.now() + TOR_EXIT_LIST_TTL_MS;
        return new Set(entries);
      })
      .catch(() => {
        torExitListPromise = null;
        torExitListExpiresAt = 0;
        torExitListRetryAt = Date.now() + 300000;
        return null;
      });
  }
  return torExitListPromise;
}

export function resetRuntimeCaches() {
  torExitListPromise = null;
  torExitListExpiresAt = 0;
  torExitListRetryAt = 0;
}

function applyCommunityFlags(detail, stopForumSpam, torExitList, target, ptr) {
  if (!detail) return detail;

  if (stopForumSpam) {
    if (typeof detail.is_abuser !== 'boolean') detail.is_abuser = stopForumSpam.is_abuser;
    detail.abuse = detail.abuse || {};
    detail.abuse.reports = stopForumSpam.reports;
  }

  if (torExitList && isValidIPv4Address(target)) {
    if (typeof detail.is_tor !== 'boolean') detail.is_tor = torExitList.has(target);
  }

  if (ptr && !detail.ptr) detail.ptr = ptr;

  return detail;
}

async function lookupIpDetails(target) {
  const [netCoffeeResult, ipapiResult, ipwhoResult, ipApiComResult, rdapResult, stopForumSpamResult, torResult, ptrResult] = await Promise.allSettled([
    lookupWithNetCoffee(target),
    lookupWithIpApiIs(target),
    lookupWithIpwho(target),
    lookupWithIpApiCom(target),
    lookupWithRdap(target),
    lookupWithStopForumSpam(target),
    getTorExitList(),
    lookupWithPtr(target),
  ]);

  const rdap = rdapResult.status === 'fulfilled' ? rdapResult.value : null;
  const stopForumSpam = stopForumSpamResult.status === 'fulfilled' ? stopForumSpamResult.value : null;
  const torExitList = torResult.status === 'fulfilled' ? torResult.value : null;
  const ptr = ptrResult.status === 'fulfilled' ? ptrResult.value : null;
  const details = [];

  // Net.Coffee 是参考项目 one-ip 的评分来源，优先作为基础数据；其余源补全缺失字段。
  if (netCoffeeResult.status === 'fulfilled' && netCoffeeResult.value) details.push(netCoffeeResult.value);
  if (ipwhoResult.status === 'fulfilled') details.push(ipwhoResult.value);
  if (ipapiResult.status === 'fulfilled') details.push(ipapiResult.value);
  if (ipApiComResult.status === 'fulfilled') details.push(ipApiComResult.value);

  const rdapDetail = buildRdapDetail(target, rdap);

  if (details.length === 0) {
    if (rdapDetail) return finalizeDetail(applyCommunityFlags(rdapDetail, stopForumSpam, torExitList, target, ptr));

    const firstError = [netCoffeeResult, ipapiResult, ipwhoResult, ipApiComResult, rdapResult]
      .find((result) => result.status === 'rejected')?.reason;
    if (firstError?.status) throw firstError;
    throw new Error('所有 IP 数据源暂不可用');
  }

  const detail = details[0];
  for (const extra of details.slice(1)) mergeDetail(detail, extra);
  if (rdapDetail) mergeDetail(detail, rdapDetail);
  applyCommunityFlags(detail, stopForumSpam, torExitList, target, ptr);

  return finalizeDetail(detail);
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const corsHeaders = getCorsHeaders(request);

    // 处理 CORS 预检请求
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: { ...corsHeaders, ...SECURITY_HEADERS },
      });
    }

    // 处理 favicon 请求（供 Google Favicon API 等外部服务抓取）
    if (url.pathname === '/favicon.ico' || url.pathname === '/favicon.png') {
      return new Response(getFaviconPng(), {
        headers: {
          'content-type': 'image/png',
          'Cache-Control': 'public, max-age=86400',
          ...SECURITY_HEADERS,
        },
      });
    }

    if (url.pathname === '/favicon.svg') {
      const svgIcon = `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#4f46e5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/></svg>`;
      return new Response(svgIcon, {
        headers: {
          'content-type': 'image/svg+xml',
          'Cache-Control': 'public, max-age=86400',
          ...SECURITY_HEADERS,
        },
      });
    }

    // 处理 API 中转请求
    if (url.pathname === '/api/ipapi') {
      if (request.method !== 'GET') {
        return new Response(JSON.stringify({ error: 'Method Not Allowed' }), {
          status: 405,
          headers: {
            'content-type': 'application/json;charset=UTF-8',
            'Allow': 'GET, OPTIONS',
            ...corsHeaders,
            ...SECURITY_HEADERS,
          },
        });
      }

      const ip = url.searchParams.get('q');

      // 输入校验：拦截无效值与占位值，避免命中上游
      if (!ip || !validateQueryTarget(ip)) {
        return new Response(JSON.stringify({ error: ip ? '无效的 IP 地址或域名格式' : '缺少查询目标' }), {
          status: 400,
          headers: {
            'content-type': 'application/json;charset=UTF-8',
            ...corsHeaders,
            ...SECURITY_HEADERS,
          },
        });
      }

      try {
        const data = await lookupIpDetails(ip);

        return new Response(JSON.stringify(data), {
          status: 200,
          headers: {
            'content-type': 'application/json;charset=UTF-8',
            'Cache-Control': 'public, max-age=60',
            ...corsHeaders,
            ...SECURITY_HEADERS,
          },
        });
      } catch (error) {
        const status = Number.isInteger(error.status) && error.status >= 400 ? error.status : 502;
        const body = error.body || { error: error.message || '所有 IP 数据源暂不可用' };

        return new Response(JSON.stringify(body), {
          status,
          headers: {
            'content-type': 'application/json;charset=UTF-8',
            ...corsHeaders,
            ...SECURITY_HEADERS,
          },
        });
      }
    }

    // 获取 Cloudflare 识别的访问者信息
    const cf = request.cf || {};
    const clientIp = request.headers.get("cf-connecting-ip") ||
      request.headers.get("x-forwarded-for") ||
      "未知";
    const country = cf.country || "XX";
    const city = cf.city || "Unknown City";
    const isp = cf.asOrganization || "Unknown ISP";

    // 将这些数据注入到 HTML 中
    const initData = {
      ip: clientIp,
      country: country,
      city: city,
      isp: isp
    };

    return new Response(renderHtml(initData), {
      headers: {
        'content-type': 'text/html;charset=UTF-8',
        'Cache-Control': 'private, no-store',
        ...SECURITY_HEADERS,
      },
    });
  },
};

function renderHtml(initData) {
  return `
<!DOCTYPE html>
<html lang="zh-CN">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>IP 哨兵 - 网络身份分析</title>
    <meta name="description" content="IP 哨兵 - 多源 IP 情报分析工具，检测代理/VPN 泄漏，评估 IP 风险等级，支持 Cloudflare、ChatGPT、X.com 等多个节点对比" />
    <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
    <link rel="icon" type="image/png" sizes="32x32" href="/favicon.png" />
    <link rel="alternate icon" href="/favicon.ico" />
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600;700&family=Noto+Sans+SC:wght@400;500;700;900&display=swap" rel="stylesheet" />

    <!-- Tailwind CSS -->
    <script src="https://cdn.tailwindcss.com"></script>

    <!-- React & Babel -->
    <script src="https://unpkg.com/react@18.2.0/umd/react.production.min.js"></script>
    <script src="https://unpkg.com/react-dom@18.2.0/umd/react-dom.production.min.js"></script>
    <script src="https://unpkg.com/@babel/standalone@7.29.7/babel.min.js"></script>

    <script>
      // 注入服务端获取的初始数据（已转义，防止 XSS）
      window.CF_DATA = ${safeJsonStringify(initData)};

      // 兼容打包器在 Function#toString 输出中插入的 __name 辅助函数
      const __name = (target, value) => {
        Object.defineProperty(target, 'name', { value, configurable: true });
        return target;
      };

      ${CLIENT_SHARED_HELPERS}

      tailwind.config = {
        darkMode: 'class',
        theme: {
          extend: {
            fontFamily: {
              sans: ['Inter', '"Noto Sans SC"', '"PingFang SC"', '"Hiragino Sans GB"', '"Microsoft YaHei"', 'sans-serif'],
              serif: ['Inter', '"Noto Sans SC"', 'sans-serif'],
              mono: ['"JetBrains Mono"', '"SF Mono"', 'Consolas', 'monospace'],
            },
            animation: {
              'fade-in': 'fadeIn 0.3s ease-out',
              'slide-up': 'slideUp 0.4s ease-out',
              float: 'float 6s ease-in-out infinite',
            },
            keyframes: {
              fadeIn: {
                '0%': { opacity: '0' },
                '100%': { opacity: '1' },
              },
              slideUp: {
                '0%': { opacity: '0', transform: 'translateY(10px)' },
                '100%': { opacity: '1', transform: 'translateY(0)' },
              },
              float: {
                '0%, 100%': { transform: 'translateY(0)' },
                '50%': { transform: 'translateY(-5px)' },
              }
            }
          },
        },
      }
    </script>
    <script>
      // 主题与风格初始化：在页面渲染前应用，防止闪烁
      (function() {
        var root = document.documentElement;
        var theme = localStorage.getItem('theme');
        var stylePreset = localStorage.getItem('style-preset');
        if (!['linear', 'original', 'apple'].includes(stylePreset)) {
          stylePreset = 'apple';
        }
        root.dataset.style = stylePreset;
        if (theme === 'dark' || (!theme && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
          root.classList.add('dark');
        }
      })();
    </script>
    <style>
      :root {
        --bg: #f6f8fb;
        --bg-2: #eef3f9;
        --surface: rgba(255, 255, 255, 0.76);
        --surface-strong: rgba(255, 255, 255, 0.88);
        --surface-tint: rgba(245, 247, 250, 0.82);
        --surface-top: rgba(255, 255, 255, 0.78);
        --surface-top-strong: rgba(255, 255, 255, 0.92);
        --surface-border: rgba(255, 255, 255, 0.56);
        --surface-border-strong: rgba(255, 255, 255, 0.58);
        --surface-highlight: rgba(255, 255, 255, 0.3);
        --surface-highlight-strong: rgba(255, 255, 255, 0.44);
        --line: rgba(15, 23, 42, 0.08);
        --line-strong: rgba(99, 102, 241, 0.18);
        --text-soft: #5f6b7a;
        --brand: #0f172a;
        --brand-2: #2563eb;
        --brand-3: #4f46e5;
        --lux: #6b7cff;
        --lux-soft: rgba(107, 124, 255, 0.14);
        --shadow-soft: 0 18px 48px rgba(15, 23, 42, 0.08);
        --shadow-strong: 0 26px 70px rgba(15, 23, 42, 0.12);
        --surface-glare: linear-gradient(135deg, rgba(255, 255, 255, 0.18), transparent 38%, transparent 72%, var(--lux-soft));
      }
      html.dark {
        --bg: #070b13;
        --bg-2: #0b1120;
        --surface: rgba(11, 17, 28, 0.78);
        --surface-strong: rgba(9, 13, 22, 0.9);
        --surface-tint: rgba(10, 16, 28, 0.86);
        --surface-top: rgba(18, 26, 43, 0.94);
        --surface-top-strong: rgba(12, 18, 31, 0.98);
        --surface-border: rgba(148, 163, 184, 0.14);
        --surface-border-strong: rgba(148, 163, 184, 0.16);
        --surface-highlight: rgba(255, 255, 255, 0.045);
        --surface-highlight-strong: rgba(255, 255, 255, 0.06);
        --line: rgba(148, 163, 184, 0.12);
        --line-strong: rgba(129, 140, 248, 0.22);
        --text-soft: #93a1b5;
        --brand: #f8fafc;
        --brand-2: #93c5fd;
        --brand-3: #818cf8;
        --lux: #8ea0ff;
        --lux-soft: rgba(142, 160, 255, 0.14);
        --shadow-soft: 0 22px 58px rgba(2, 8, 23, 0.42);
        --shadow-strong: 0 30px 78px rgba(2, 8, 23, 0.34);
        --surface-glare: linear-gradient(145deg, rgba(255, 255, 255, 0.05), transparent 40%, transparent 72%, rgba(142, 160, 255, 0.08));
      }
      html.dark body {
        color-scheme: dark;
        background:
          radial-gradient(56rem 56rem at -12% -18%, rgba(96, 165, 250, 0.16), transparent 50%),
          radial-gradient(46rem 46rem at 118% -6%, rgba(129, 140, 248, 0.14), transparent 42%),
          radial-gradient(38rem 38rem at 50% 112%, rgba(15, 23, 42, 0.22), transparent 60%),
          linear-gradient(160deg, var(--bg) 0%, var(--bg-2) 100%);
        background-attachment: fixed;
      }
      body {
        min-height: 100vh;
        background:
          radial-gradient(56rem 56rem at -12% -18%, rgba(96, 165, 250, 0.14), transparent 52%),
          radial-gradient(46rem 46rem at 118% -6%, rgba(129, 140, 248, 0.11), transparent 44%),
          radial-gradient(36rem 36rem at 50% 110%, rgba(255, 255, 255, 0.32), transparent 56%),
          linear-gradient(160deg, var(--bg) 0%, var(--bg-2) 100%);
        background-attachment: fixed;
      }
      body:before {
        content: '';
        position: fixed;
        inset: 0;
        pointer-events: none;
        background:
          radial-gradient(circle at 20% 18%, rgba(255, 255, 255, 0.5), transparent 18%),
          radial-gradient(circle at 80% 8%, rgba(255, 255, 255, 0.24), transparent 14%);
        opacity: 0.28;
      }
      html.dark body:before {
        background:
          radial-gradient(circle at 20% 18%, rgba(129, 140, 248, 0.16), transparent 18%),
          radial-gradient(circle at 80% 8%, rgba(56, 189, 248, 0.12), transparent 14%);
        opacity: 0.42;
      }
      .app-shell {
        position: relative;
        isolation: isolate;
      }
      .app-shell:before {
        content: '';
        position: fixed;
        inset: 0;
        pointer-events: none;
        opacity: 0.36;
        background-image: linear-gradient(rgba(14, 116, 144, 0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(14, 116, 144, 0.05) 1px, transparent 1px);
        background-size: 30px 30px;
        mask-image: radial-gradient(circle at 40% 20%, black 20%, transparent 80%);
      }
      html.dark .app-shell:before {
        opacity: 0.24;
        background-image: linear-gradient(rgba(129, 140, 248, 0.08) 1px, transparent 1px), linear-gradient(90deg, rgba(129, 140, 248, 0.08) 1px, transparent 1px);
      }
      .surface-card {
        position: relative;
        overflow: hidden;
        isolation: isolate;
        background: linear-gradient(180deg, var(--surface-top), var(--surface));
        border: 1px solid var(--surface-border);
        box-shadow: var(--shadow-soft), inset 0 1px 0 var(--surface-highlight);
        backdrop-filter: blur(24px) saturate(160%);
      }
      .surface-strong {
        position: relative;
        overflow: hidden;
        isolation: isolate;
        background: linear-gradient(180deg, var(--surface-top-strong), var(--surface-tint));
        border: 1px solid var(--surface-border-strong);
        box-shadow: var(--shadow-soft), inset 0 1px 0 var(--surface-highlight-strong);
      }
      .surface-card:after,
      .surface-strong:after {
        content: '';
        position: absolute;
        inset: 0;
        pointer-events: none;
        background: var(--surface-glare);
      }
      .header-shell {
        background: linear-gradient(180deg, rgba(255, 255, 255, 0.72), rgba(255, 255, 255, 0.54));
      }
      html.dark .header-shell {
        background: linear-gradient(180deg, rgba(8, 11, 18, 0.88), rgba(8, 11, 18, 0.7));
      }
      .title-gradient {
        background: linear-gradient(180deg, #0f172a 0%, #334155 58%, #2563eb 100%);
        -webkit-background-clip: text;
        background-clip: text;
        color: transparent;
        text-shadow: 0 8px 24px rgba(15, 23, 42, 0.1);
      }
      html.dark .title-gradient {
        background: linear-gradient(180deg, #ffffff 0%, #cbd5e1 58%, #93c5fd 100%);
        -webkit-background-clip: text;
        background-clip: text;
        color: transparent;
      }
      .brand-badge {
        background: linear-gradient(145deg, rgba(15, 23, 42, 0.98) 0%, rgba(30, 41, 59, 0.95) 52%, rgba(79, 70, 229, 0.92) 100%);
        box-shadow: 0 14px 30px rgba(15, 23, 42, 0.18), inset 0 1px 0 rgba(255, 255, 255, 0.22);
      }
      .brand-title {
        letter-spacing: 0.02em;
        text-shadow: 0 8px 20px rgba(15, 23, 42, 0.06);
      }
      .hero-title {
        letter-spacing: -0.045em;
        font-feature-settings: 'liga' 1, 'kern' 1, 'cv11' 1;
      }
      .app-orb {
        position: absolute;
        border-radius: 9999px;
        filter: blur(46px);
        pointer-events: none;
        z-index: 0;
      }
      .app-orb-1 {
        width: 220px;
        height: 220px;
        top: 90px;
        left: -70px;
        background: rgba(96, 165, 250, 0.14);
      }
      .app-orb-2 {
        width: 240px;
        height: 240px;
        top: 200px;
        right: -90px;
        background: rgba(99, 102, 241, 0.12);
      }
      html.dark .app-orb-1 {
        background: rgba(96, 165, 250, 0.12);
      }
      html.dark .app-orb-2 {
        background: rgba(129, 140, 248, 0.12);
      }
      .hero-chip {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 8px 12px;
        border-radius: 9999px;
        border: 1px solid rgba(148, 163, 184, 0.16);
        background: linear-gradient(180deg, rgba(255, 255, 255, 0.86), rgba(248, 250, 252, 0.74));
        box-shadow: 0 10px 24px rgba(15, 23, 42, 0.05), inset 0 1px 0 rgba(255, 255, 255, 0.64);
        font-size: 12px;
        font-weight: 600;
        letter-spacing: 0.01em;
        color: #556274;
      }
      html.dark .hero-chip {
        background: linear-gradient(180deg, rgba(18, 26, 42, 0.84), rgba(10, 15, 26, 0.7));
        border-color: rgba(129, 140, 248, 0.14);
        box-shadow: 0 12px 30px rgba(2, 8, 23, 0.28), inset 0 1px 0 rgba(255, 255, 255, 0.05);
        color: #d8e2f2;
      }
      .hero-panel {
        position: relative;
        box-shadow: var(--shadow-soft), inset 0 1px 0 rgba(255, 255, 255, 0.6);
      }
      .hero-panel:before {
        content: '';
        position: absolute;
        top: 20px;
        left: 24px;
        width: 140px;
        height: 2px;
        border-radius: 9999px;
        background: linear-gradient(90deg, transparent, var(--lux), rgba(147, 197, 253, 0.22), transparent);
        opacity: 0.92;
      }
      .hero-panel:after {
        content: '';
        position: absolute;
        inset: auto 28px 24px auto;
        width: 96px;
        height: 96px;
        border-radius: 9999px;
        background: radial-gradient(circle, rgba(129, 140, 248, 0.12), transparent 72%);
        pointer-events: none;
      }
      .status-card {
        border-color: rgba(255, 255, 255, 0.62);
        box-shadow: var(--shadow-soft), inset 0 1px 0 rgba(255, 255, 255, 0.45);
      }
      .status-card:before {
        content: '';
        position: absolute;
        top: 0;
        left: 14px;
        right: 14px;
        height: 1px;
        background: linear-gradient(90deg, transparent, var(--lux), rgba(147, 197, 253, 0.3), transparent);
        opacity: 0.8;
        z-index: 2;
      }
      .status-card:hover {
        box-shadow: var(--shadow-strong), inset 0 1px 0 rgba(255, 255, 255, 0.52);
      }
      html.dark .status-card {
        border-color: var(--surface-border);
      }
      .status-card__header {
        background: linear-gradient(135deg, rgba(255, 255, 255, 0.66), rgba(248, 250, 252, 0.8));
      }
      html.dark .status-card__header {
        background: linear-gradient(135deg, rgba(24, 31, 46, 0.78), rgba(15, 23, 42, 0.84));
      }
      .ip-glow {
        text-shadow: 0 12px 28px rgba(15, 23, 42, 0.08);
      }
      .subtle-pill {
        border: 1px solid rgba(148, 163, 184, 0.14);
        background: linear-gradient(180deg, rgba(248, 250, 252, 0.94), rgba(241, 245, 249, 0.9));
        box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.68);
      }
      html.dark .subtle-pill {
        border-color: rgba(129, 140, 248, 0.12);
        background: linear-gradient(180deg, rgba(22, 30, 46, 0.88), rgba(11, 17, 28, 0.96));
      }
      .connectivity-section {
        margin-top: 28px;
      }
      .connectivity-panel {
        padding: 0;
      }
      .connectivity-grid {
        display: grid;
        grid-template-columns: minmax(0, 1fr);
        gap: 24px;
      }
      @media (min-width: 768px) {
        .connectivity-grid {
          grid-template-columns: repeat(2, minmax(0, 1fr));
        }
      }
      @media (min-width: 1024px) {
        .connectivity-grid {
          grid-template-columns: repeat(4, minmax(0, 1fr));
        }
      }
      .connectivity-card {
        min-width: 0;
        border: 1px solid var(--surface-border);
        border-radius: 1rem;
        background: linear-gradient(180deg, var(--surface-top), var(--surface));
        box-shadow: var(--shadow-soft), inset 0 1px 0 var(--surface-highlight);
        backdrop-filter: blur(24px) saturate(160%);
        padding: 10px 12px;
        display: flex;
        align-items: center;
        gap: 7px;
      }
      html.dark .connectivity-card {
        border-color: var(--surface-border);
      }
      .connectivity-card:hover {
        background: linear-gradient(180deg, color-mix(in srgb, var(--surface-top) 90%, white 10%), color-mix(in srgb, var(--surface) 92%, white 8%));
      }
      html.dark .connectivity-card:hover {
        background: linear-gradient(180deg, color-mix(in srgb, var(--surface-top) 92%, white 8%), color-mix(in srgb, var(--surface) 96%, white 4%));
      }
      .connectivity-icon {
        width: 16px;
        height: 16px;
        border-radius: 3px;
        object-fit: contain;
        flex: 0 0 auto;
      }
      .connectivity-main {
        min-width: 0;
        flex: 1 1 auto;
      }
      .connectivity-name {
        display: block;
        min-width: 0;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
        font-size: 0.82rem;
        font-weight: 600;
        line-height: 1.25;
        color: var(--brand);
      }
      .connectivity-dots {
        display: flex;
        gap: 2px;
        margin-top: 4px;
      }
      .connectivity-dot {
        width: 6px;
        height: 6px;
        border-radius: 9999px;
      }
      .connectivity-ms {
        min-width: 4.2em;
        text-align: right;
        white-space: nowrap;
        flex-shrink: 0;
        font-size: 0.95rem;
        font-weight: 700;
        line-height: 1;
        font-variant-numeric: tabular-nums;
      }
      .connectivity-ms-value {
        display: inline-block;
        animation: latencyNumberSwap 260ms cubic-bezier(0.22, 1, 0.36, 1);
      }
      @keyframes latencyNumberSwap {
        0% { opacity: 0; transform: translateY(5px); filter: blur(2px); }
        100% { opacity: 1; transform: translateY(0); filter: blur(0); }
      }
      @media (max-width: 768px) {
        .connectivity-panel {
          padding: 0;
        }
        .connectivity-card {
          padding: 7px 8px;
          gap: 6px;
        }
        .connectivity-name {
          font-size: 0.78rem;
        }
        .connectivity-ms {
          font-size: 0.86rem;
        }
        .connectivity-dot {
          width: 5px;
          height: 5px;
        }
      }
      @media (max-width: 360px) {
        .connectivity-grid {
          grid-template-columns: 1fr;
        }
      }
      .icon-button {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        border-radius: 14px;
        border: 1px solid rgba(148, 163, 184, 0.16);
        background: linear-gradient(180deg, rgba(255, 255, 255, 0.92), rgba(248, 250, 252, 0.84));
        box-shadow: 0 10px 24px rgba(15, 23, 42, 0.06), inset 0 1px 0 rgba(255, 255, 255, 0.7);
        backdrop-filter: blur(14px);
      }
      .icon-button:hover {
        transform: translateY(-1px);
        box-shadow: 0 14px 32px rgba(15, 23, 42, 0.1), inset 0 1px 0 rgba(255, 255, 255, 0.8);
      }
      html.dark .icon-button {
        border-color: rgba(129, 140, 248, 0.14);
        background: linear-gradient(180deg, rgba(18, 26, 42, 0.86), rgba(10, 15, 26, 0.72));
        box-shadow: 0 12px 28px rgba(2, 8, 23, 0.28), inset 0 1px 0 rgba(255, 255, 255, 0.06);
      }
      .action-button {
        border: 1px solid rgba(148, 163, 184, 0.16);
        background: linear-gradient(135deg, rgba(255, 255, 255, 0.96), rgba(248, 250, 252, 0.92));
        box-shadow: 0 12px 28px rgba(15, 23, 42, 0.06), inset 0 1px 0 rgba(255, 255, 255, 0.7);
      }
      .action-button:hover {
        transform: translateY(-1px);
        box-shadow: 0 16px 36px rgba(15, 23, 42, 0.1), inset 0 1px 0 rgba(255, 255, 255, 0.78);
      }
      html.dark .action-button {
        border-color: rgba(129, 140, 248, 0.14);
        background: linear-gradient(135deg, rgba(18, 26, 42, 0.9), rgba(9, 15, 26, 0.78));
        box-shadow: 0 14px 34px rgba(2, 8, 23, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.06);
      }
      .footer-shell {
        border: 1px solid rgba(255, 255, 255, 0.54);
        box-shadow: var(--shadow-soft), inset 0 1px 0 rgba(255, 255, 255, 0.48);
      }
      html.dark .footer-shell {
        border-color: rgba(255, 255, 255, 0.08);
      }
      html[data-style="original"] {
        --bg: #f4f8ff;
        --bg-2: #f8f7ff;
        --surface: rgba(255, 255, 255, 0.82);
        --surface-strong: rgba(255, 255, 255, 0.95);
        --surface-tint: rgba(240, 249, 255, 0.7);
        --line: rgba(14, 116, 144, 0.14);
        --line-strong: rgba(14, 116, 144, 0.22);
        --text-soft: #4b5563;
        --brand: #0e7490;
        --brand-2: #0284c7;
        --brand-3: #14b8a6;
        --lux: #14b8a6;
        --lux-soft: rgba(20, 184, 166, 0.12);
        --shadow-soft: 0 20px 55px rgba(15, 23, 42, 0.08);
        --shadow-strong: 0 26px 75px rgba(14, 116, 144, 0.16);
      }
      html.dark[data-style="original"] {
        --bg: #07121d;
        --bg-2: #101a2d;
        --surface: rgba(14, 25, 41, 0.74);
        --surface-strong: rgba(11, 22, 37, 0.94);
        --surface-tint: rgba(8, 19, 35, 0.82);
        --surface-top: rgba(10, 23, 39, 0.94);
        --surface-top-strong: rgba(6, 18, 33, 0.98);
        --surface-border: rgba(56, 189, 248, 0.16);
        --surface-border-strong: rgba(103, 232, 249, 0.18);
        --line: rgba(56, 189, 248, 0.22);
        --line-strong: rgba(103, 232, 249, 0.26);
        --text-soft: #94a3b8;
        --brand: #f8fafc;
        --brand-2: #38bdf8;
        --brand-3: #22d3ee;
        --lux: #67e8f9;
        --lux-soft: rgba(103, 232, 249, 0.14);
        --shadow-soft: 0 24px 60px rgba(2, 8, 23, 0.42);
        --shadow-strong: 0 32px 80px rgba(2, 132, 199, 0.22);
        --surface-glare: linear-gradient(145deg, rgba(103, 232, 249, 0.06), transparent 40%, transparent 74%, rgba(34, 211, 238, 0.1));
      }
      html[data-style="original"] .header-shell {
        background: linear-gradient(180deg, rgba(255, 255, 255, 0.78), rgba(255, 255, 255, 0.62));
      }
      html[data-style="original"] body {
        background:
          radial-gradient(60rem 60rem at -15% -20%, rgba(34, 211, 238, 0.18), transparent 52%),
          radial-gradient(52rem 52rem at 120% -10%, rgba(59, 130, 246, 0.14), transparent 46%),
          radial-gradient(40rem 40rem at 50% 110%, rgba(14, 165, 233, 0.07), transparent 58%),
          linear-gradient(160deg, var(--bg) 0%, var(--bg-2) 100%);
        background-attachment: fixed;
      }
      html[data-style="original"] .app-shell:before {
        opacity: 0.34;
        background-image: linear-gradient(rgba(14, 116, 144, 0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(14, 116, 144, 0.05) 1px, transparent 1px);
      }
      html.dark[data-style="original"] .header-shell {
        background: linear-gradient(180deg, rgba(4, 10, 20, 0.9), rgba(4, 10, 20, 0.68));
      }
      html.dark[data-style="original"] body {
        background:
          radial-gradient(60rem 60rem at -15% -20%, rgba(34, 211, 238, 0.16), transparent 50%),
          radial-gradient(52rem 52rem at 120% -10%, rgba(59, 130, 246, 0.14), transparent 42%),
          radial-gradient(36rem 36rem at 50% 112%, rgba(8, 47, 73, 0.24), transparent 60%),
          linear-gradient(160deg, var(--bg) 0%, var(--bg-2) 100%);
        background-attachment: fixed;
      }
      html.dark[data-style="original"] body:before {
        background:
          radial-gradient(circle at 20% 18%, rgba(103, 232, 249, 0.14), transparent 18%),
          radial-gradient(circle at 80% 8%, rgba(34, 211, 238, 0.12), transparent 14%);
      }
      html.dark[data-style="original"] .app-shell:before {
        opacity: 0.26;
        background-image: linear-gradient(rgba(34, 211, 238, 0.07) 1px, transparent 1px), linear-gradient(90deg, rgba(34, 211, 238, 0.07) 1px, transparent 1px);
      }
      html[data-style="original"] .title-gradient {
        background: linear-gradient(95deg, #0e7490 0%, #0369a1 55%, #14b8a6 100%);
        -webkit-background-clip: text;
        background-clip: text;
        color: transparent;
        text-shadow: 0 8px 30px rgba(14, 116, 144, 0.18);
      }
      html.dark[data-style="original"] .title-gradient {
        background: linear-gradient(95deg, #67e8f9 0%, #38bdf8 55%, #22d3ee 100%);
        -webkit-background-clip: text;
        background-clip: text;
        color: transparent;
      }
      html[data-style="original"] .brand-badge {
        background: linear-gradient(135deg, #06b6d4 0%, #0284c7 55%, #0ea5e9 100%);
        box-shadow: 0 18px 36px rgba(14, 165, 233, 0.28), inset 0 1px 0 rgba(255, 255, 255, 0.26);
      }
      html[data-style="original"] .brand-title {
        letter-spacing: 0.08em;
      }
      html[data-style="original"] .hero-title {
        letter-spacing: 0.01em;
      }
      html[data-style="original"] .app-orb-1 {
        background: rgba(34, 211, 238, 0.22);
      }
      html[data-style="original"] .app-orb-2 {
        background: rgba(56, 189, 248, 0.2);
      }
      html.dark[data-style="original"] .app-orb-1 {
        background: rgba(34, 211, 238, 0.12);
      }
      html.dark[data-style="original"] .app-orb-2 {
        background: rgba(56, 189, 248, 0.14);
      }
      html[data-style="original"] .hero-chip {
        border-color: rgba(14, 116, 144, 0.15);
        background: linear-gradient(180deg, rgba(255, 255, 255, 0.92), rgba(236, 254, 255, 0.76));
        box-shadow: 0 14px 28px rgba(14, 116, 144, 0.08), inset 0 1px 0 rgba(255, 255, 255, 0.72);
        color: #0f766e;
      }
      html.dark[data-style="original"] .hero-chip {
        background: linear-gradient(180deg, rgba(15, 23, 42, 0.78), rgba(8, 47, 73, 0.5));
        border-color: rgba(56, 189, 248, 0.22);
        box-shadow: 0 14px 34px rgba(2, 8, 23, 0.24), inset 0 1px 0 rgba(255, 255, 255, 0.05);
        color: #67e8f9;
      }
      html[data-style="original"] .hero-panel:before {
        width: 180px;
        height: 4px;
        background: linear-gradient(90deg, transparent, rgba(14, 165, 233, 0.8), rgba(20, 184, 166, 0.18), transparent);
      }
      html[data-style="original"] .hero-panel:after {
        width: 120px;
        height: 120px;
        background: radial-gradient(circle, rgba(20, 184, 166, 0.12), transparent 70%);
      }
      html[data-style="original"] .status-card:before {
        background: linear-gradient(90deg, transparent, rgba(14, 165, 233, 0.85), rgba(34, 211, 238, 0.32), transparent);
      }
      html[data-style="apple"] {
        --bg: #f5f7fa;
        --bg-2: #edf1f7;
        --surface: rgba(255, 255, 255, 0.72);
        --surface-strong: rgba(255, 255, 255, 0.86);
        --surface-tint: rgba(246, 248, 251, 0.8);
        --line: rgba(15, 23, 42, 0.06);
        --line-strong: rgba(96, 165, 250, 0.16);
        --text-soft: #667085;
        --brand: #111827;
        --brand-2: #3b82f6;
        --brand-3: #93c5fd;
        --lux: #7aa2ff;
        --lux-soft: rgba(122, 162, 255, 0.12);
        --shadow-soft: 0 20px 56px rgba(15, 23, 42, 0.08);
        --shadow-strong: 0 28px 78px rgba(15, 23, 42, 0.1);
      }
      html.dark[data-style="apple"] {
        --bg: #050912;
        --bg-2: #0a0f19;
        --surface: rgba(12, 18, 29, 0.74);
        --surface-strong: rgba(8, 12, 22, 0.88);
        --surface-tint: rgba(10, 16, 28, 0.84);
        --surface-top: rgba(14, 20, 31, 0.94);
        --surface-top-strong: rgba(9, 14, 24, 0.98);
        --surface-border: rgba(191, 219, 254, 0.1);
        --surface-border-strong: rgba(191, 219, 254, 0.12);
        --line: rgba(148, 163, 184, 0.1);
        --line-strong: rgba(147, 197, 253, 0.18);
        --text-soft: #98a4b6;
        --brand: #f8fafc;
        --brand-2: #93c5fd;
        --brand-3: #bfdbfe;
        --lux: #9cc0ff;
        --lux-soft: rgba(156, 192, 255, 0.12);
        --shadow-soft: 0 22px 60px rgba(2, 8, 23, 0.42);
        --shadow-strong: 0 30px 80px rgba(2, 8, 23, 0.32);
        --surface-glare: linear-gradient(145deg, rgba(255, 255, 255, 0.05), transparent 42%, transparent 76%, rgba(147, 197, 253, 0.08));
      }
      html[data-style="apple"] .header-shell {
        background: linear-gradient(180deg, rgba(255, 255, 255, 0.82), rgba(255, 255, 255, 0.64));
      }
      html[data-style="apple"] body {
        background:
          radial-gradient(54rem 54rem at -12% -18%, rgba(191, 219, 254, 0.18), transparent 52%),
          radial-gradient(44rem 44rem at 118% -6%, rgba(148, 163, 184, 0.1), transparent 46%),
          radial-gradient(36rem 36rem at 50% 110%, rgba(255, 255, 255, 0.38), transparent 56%),
          linear-gradient(160deg, var(--bg) 0%, var(--bg-2) 100%);
        background-attachment: fixed;
      }
      html[data-style="apple"] .app-shell:before {
        opacity: 0.26;
        background-image: linear-gradient(rgba(148, 163, 184, 0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(148, 163, 184, 0.05) 1px, transparent 1px);
      }
      html.dark[data-style="apple"] .header-shell {
        background: linear-gradient(180deg, rgba(7, 10, 16, 0.82), rgba(7, 10, 16, 0.64));
      }
      html.dark[data-style="apple"] body {
        background:
          radial-gradient(54rem 54rem at -12% -18%, rgba(147, 197, 253, 0.14), transparent 50%),
          radial-gradient(44rem 44rem at 118% -6%, rgba(148, 163, 184, 0.1), transparent 44%),
          radial-gradient(36rem 36rem at 50% 112%, rgba(15, 23, 42, 0.22), transparent 60%),
          linear-gradient(160deg, var(--bg) 0%, var(--bg-2) 100%);
        background-attachment: fixed;
      }
      html.dark[data-style="apple"] body:before {
        background:
          radial-gradient(circle at 20% 18%, rgba(191, 219, 254, 0.14), transparent 18%),
          radial-gradient(circle at 80% 8%, rgba(147, 197, 253, 0.1), transparent 14%);
      }
      html.dark[data-style="apple"] .app-shell:before {
        opacity: 0.22;
        background-image: linear-gradient(rgba(148, 163, 184, 0.06) 1px, transparent 1px), linear-gradient(90deg, rgba(148, 163, 184, 0.06) 1px, transparent 1px);
      }
      html[data-style="apple"] .title-gradient {
        background: linear-gradient(180deg, #111827 0%, #4b5563 66%, #60a5fa 100%);
        -webkit-background-clip: text;
        background-clip: text;
        color: transparent;
        text-shadow: 0 8px 24px rgba(15, 23, 42, 0.08);
      }
      html.dark[data-style="apple"] .title-gradient {
        background: linear-gradient(180deg, #ffffff 0%, #dbe3ee 68%, #93c5fd 100%);
        -webkit-background-clip: text;
        background-clip: text;
        color: transparent;
      }
      html[data-style="apple"] .brand-badge {
        background: linear-gradient(145deg, rgba(17, 24, 39, 0.96) 0%, rgba(59, 130, 246, 0.82) 100%);
        box-shadow: 0 14px 32px rgba(15, 23, 42, 0.16), inset 0 1px 0 rgba(255, 255, 255, 0.26);
      }
      html[data-style="apple"] .brand-title {
        letter-spacing: -0.01em;
      }
      html[data-style="apple"] .hero-title {
        letter-spacing: -0.055em;
      }
      html[data-style="apple"] .app-orb-1 {
        background: rgba(148, 163, 184, 0.14);
      }
      html[data-style="apple"] .app-orb-2 {
        background: rgba(96, 165, 250, 0.1);
      }
      html.dark[data-style="apple"] .app-orb-1 {
        background: rgba(148, 163, 184, 0.1);
      }
      html.dark[data-style="apple"] .app-orb-2 {
        background: rgba(96, 165, 250, 0.12);
      }
      html[data-style="apple"] .hero-chip {
        border-color: rgba(148, 163, 184, 0.14);
        background: linear-gradient(180deg, rgba(255, 255, 255, 0.88), rgba(248, 250, 252, 0.78));
        box-shadow: 0 10px 24px rgba(15, 23, 42, 0.05), inset 0 1px 0 rgba(255, 255, 255, 0.7);
        color: #526174;
      }
      html.dark[data-style="apple"] .hero-chip {
        background: linear-gradient(180deg, rgba(15, 23, 42, 0.78), rgba(15, 23, 42, 0.6));
        border-color: rgba(255, 255, 255, 0.08);
        box-shadow: 0 12px 30px rgba(2, 8, 23, 0.24), inset 0 1px 0 rgba(255, 255, 255, 0.04);
        color: #d6deea;
      }
      html[data-style="apple"] .hero-panel:before {
        width: 120px;
        height: 2px;
        background: linear-gradient(90deg, transparent, rgba(96, 165, 250, 0.75), rgba(191, 219, 254, 0.28), transparent);
      }
      html[data-style="apple"] .hero-panel:after {
        width: 90px;
        height: 90px;
        background: radial-gradient(circle, rgba(191, 219, 254, 0.14), transparent 72%);
      }
      html[data-style="apple"] .status-card:before {
        background: linear-gradient(90deg, transparent, rgba(96, 165, 250, 0.55), rgba(191, 219, 254, 0.22), transparent);
      }
      .ip-addr {
        word-break: break-all;
        overflow-wrap: anywhere;
        line-height: 1.62;
        letter-spacing: 0.01em;
      }
      .ip-addr-inline {
        display: block;
        max-width: 100%;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        line-height: 1.28;
      }
      .ip-v6-wrap {
        display: inline-flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        line-height: 1.08;
        letter-spacing: 0.008em;
        max-width: 100%;
        width: 100%;
      }
      .ip-v6-line {
        max-width: 100%;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
        width: 100%;
      }
      .scrollbar-hide::-webkit-scrollbar { display: none; }
      .scrollbar-hide { -ms-overflow-style: none; scrollbar-width: none; }
      .ip-detail-overlay {
        --detail-paper: #ffffff;
        --detail-wash: #f5f7fa;
        --detail-ink: #172536;
        --detail-muted: #596a7e;
        --detail-line: #e2e8ef;
        --detail-accent: #0369a1;
        position: fixed;
        inset: 0;
        z-index: 50;
        display: grid;
        place-items: center;
        padding: 24px;
        color: var(--detail-ink);
        font-family: 'Noto Sans SC', 'PingFang SC', sans-serif;
      }
      html.dark .ip-detail-overlay {
        --detail-paper: #111b29;
        --detail-wash: #0c1420;
        --detail-ink: #edf3fa;
        --detail-muted: #a2b2c6;
        --detail-line: #29374a;
        --detail-accent: #7dd3fc;
      }
      .ip-detail-backdrop { position: absolute; inset: 0; background: rgba(8, 17, 30, 0.64); }
      .ip-detail-panel {
        position: relative;
        display: flex;
        flex-direction: column;
        width: min(100%, 960px);
        max-height: min(90vh, 1040px);
        max-height: min(90dvh, 1040px);
        min-height: 0;
        overflow: hidden;
        border: 1px solid var(--detail-line);
        border-radius: 24px;
        background: var(--detail-paper);
        box-shadow: 0 32px 96px rgba(2, 8, 23, 0.28);
        animation: slideUp 0.24s ease-out;
      }
      .ip-detail-toolbar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 16px;
        flex-shrink: 0;
        padding: 12px 24px;
        border-bottom: 1px solid var(--detail-line);
      }
      .ip-detail-toolbar-title { display: flex; align-items: center; gap: 10px; }
      .ip-detail-toolbar-title > svg { width: 20px; height: 20px; color: var(--detail-muted); }
      .ip-detail-toolbar h2 { font-size: 16px; font-weight: 700; }
      .ip-detail-close, .ip-detail-copy, .ip-detail-retry {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
        min-width: 44px;
        min-height: 44px;
        border: 1px solid var(--detail-line);
        border-radius: 12px;
        background: var(--detail-paper);
        color: var(--detail-muted);
        transition: background 0.15s, color 0.15s;
      }
      .ip-detail-close { border-color: transparent; }
      .ip-detail-copy { padding: 0 12px; font-size: 13px; white-space: nowrap; color: var(--detail-accent); }
      .ip-detail-retry { padding: 0 20px; margin-top: 24px; color: var(--detail-accent); font-size: 16px; }
      .ip-detail-close:hover, .ip-detail-copy:hover, .ip-detail-retry:hover { background: var(--detail-wash); color: var(--detail-accent); }
      .ip-detail-close svg, .ip-detail-copy svg { width: 18px; height: 18px; }
      .ip-detail-overlay :focus-visible { outline: 2px solid var(--detail-accent); outline-offset: -3px; box-shadow: none; }
      .ip-detail-copy:disabled { cursor: wait; opacity: 0.65; }
      .ip-detail-body { min-height: 0; overflow-y: auto; overscroll-behavior: contain; scrollbar-gutter: stable; }
      .ip-detail-overview {
        display: grid;
        grid-template-columns: minmax(0, 1fr) auto;
        align-items: center;
        gap: 32px;
        padding: 28px 32px;
      }
      .ip-detail-address-label { margin-bottom: 8px; color: var(--detail-muted); font-size: 13px; }
      .ip-detail-address { margin: 0; font: 700 clamp(24px, 3vw, 36px)/1.4 'JetBrains Mono', Consolas, monospace; letter-spacing: -0.055em; overflow-wrap: anywhere; }
      .ip-detail-meta { display: flex; align-items: flex-start; gap: 8px; margin-top: 14px; color: var(--detail-muted); font-size: 14px; line-height: 1.7; overflow-wrap: anywhere; }
      .ip-detail-meta > svg { flex-shrink: 0; width: 18px; height: 18px; margin-top: 3px; }
      .ip-detail-tags { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-top: 16px; }
      .ip-detail-tag { padding: 5px 10px; border: 1px solid var(--detail-line); border-radius: 12px; color: var(--detail-muted); font: 500 12px/1.5 'JetBrains Mono', monospace; }
      .ip-detail-copy-status { color: var(--detail-muted); font-size: 12px; }
      .ip-detail-score { display: flex; align-items: center; gap: 16px; padding-left: 28px; border-left: 1px solid var(--detail-line); }
      .ip-detail-score-ring { position: relative; flex-shrink: 0; width: 108px; height: 108px; }
      .ip-detail-score-ring > svg { width: 100%; height: 100%; transform: rotate(-90deg); }
      .ip-detail-score-track { stroke: var(--detail-line); }
      .ip-detail-score-value { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; }
      .ip-detail-score-value strong { font: 700 32px/1.15 'JetBrains Mono', monospace; letter-spacing: -0.06em; }
      .ip-detail-score-value small { margin-top: 4px; color: var(--detail-muted); font: 12px/1.4 'JetBrains Mono', monospace; }
      .ip-detail-score-caption { max-width: 104px; }
      .ip-detail-score-caption strong { display: block; font-size: 16px; font-weight: 700; color: var(--detail-ink); }
      .ip-detail-score-caption p { margin-top: 6px; font-size: 12px; line-height: 1.8; color: var(--detail-muted); }
      .ip-detail-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; padding: 24px 32px 32px; border-top: 1px solid var(--detail-line); background: var(--detail-wash); }
      .ip-detail-section { min-width: 0; padding: 20px; border: 1px solid var(--detail-line); border-radius: 12px; background: var(--detail-paper); }
      .ip-detail-section-wide { grid-column: 1 / -1; }
      .ip-detail-section-title { display: flex; align-items: center; gap: 10px; margin-bottom: 12px; padding-bottom: 12px; border-bottom: 1px solid var(--detail-line); }
      .ip-detail-section-title > svg { width: 18px; height: 18px; color: var(--detail-muted); }
      .ip-detail-section-title h3 { font-size: 16px; font-weight: 700; letter-spacing: 0.02em; }
      .ip-detail-row { display: grid; grid-template-columns: 104px minmax(0, 1fr); align-items: start; gap: 12px; padding: 9px 0; font-size: 16px; line-height: 1.6; }
      .ip-detail-row + .ip-detail-row { border-top: 1px solid var(--detail-line); }
      .ip-detail-row dt { color: var(--detail-muted); font-size: 14px; }
      .ip-detail-row dd { min-width: 0; margin: 0; font-weight: 500; text-align: right; overflow-wrap: anywhere; }
      .ip-detail-section-wide .ip-detail-rows { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); column-gap: 32px; }
      .ip-detail-section-wide .ip-detail-row:nth-child(2) { border-top: 0; }
      .ip-detail-badge { display: inline-flex; align-items: center; gap: 5px; padding: 3px 9px; border: 1px solid var(--detail-line); border-radius: 12px; font-size: 12px; font-weight: 500; color: var(--detail-muted); background: var(--detail-wash); }
      .ip-detail-badge > svg { width: 13px; height: 13px; }
      .ip-detail-badge-clear { color: #166534; background: #f0fdf4; border-color: #bbf7d0; }
      .ip-detail-badge-risk { color: #b91c1c; background: #fef2f2; border-color: #fecaca; }
      html.dark .ip-detail-badge-clear { color: #86efac; background: #122b24; border-color: #285444; }
      html.dark .ip-detail-badge-risk { color: #fca5a5; background: #321d27; border-color: #64303c; }
      .ip-detail-footer { display: flex; align-items: center; gap: 8px; flex-shrink: 0; padding: 14px 24px; border-top: 1px solid var(--detail-line); color: var(--detail-muted); font-size: 12px; line-height: 1.8; }
      .ip-detail-footer > svg { width: 15px; height: 15px; flex-shrink: 0; }
      .ip-detail-state { display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 320px; padding: 40px 24px; text-align: center; }
      .ip-detail-state-icon { display: grid; place-items: center; width: 64px; height: 64px; margin-bottom: 20px; border: 1px solid var(--detail-line); border-radius: 12px; background: var(--detail-wash); color: var(--detail-muted); }
      .ip-detail-state h3 { font-size: 20px; font-weight: 700; }
      .ip-detail-state p { max-width: 360px; margin-top: 12px; color: var(--detail-muted); font-size: 16px; line-height: 1.8; overflow-wrap: anywhere; }
      .ip-detail-state-address { font-family: 'JetBrains Mono', monospace; }
      @media (max-width: 760px) {
        .ip-detail-overview { gap: 20px; padding: 24px; }
        .ip-detail-score { padding-left: 20px; }
        .ip-detail-score-caption { display: none; }
        .ip-detail-grid { padding: 20px 24px 24px; }
        .ip-detail-row { grid-template-columns: 88px minmax(0, 1fr); gap: 8px; }
      }
      @media (max-width: 600px) {
        .ip-detail-overlay { padding: 8px; }
        .ip-detail-panel { max-height: 96vh; max-height: 96dvh; border-radius: 24px; }
        .ip-detail-toolbar { padding: 10px 16px; }
        .ip-detail-overview { grid-template-columns: minmax(0, 1fr); gap: 20px; padding: 24px 20px; }
        .ip-detail-address { font-size: 26px; }
        .ip-detail-score { padding: 16px 0 0; border-left: 0; border-top: 1px solid var(--detail-line); }
        .ip-detail-score-ring { width: 88px; height: 88px; }
        .ip-detail-score-value strong { font-size: 28px; }
        .ip-detail-score-caption { display: block; max-width: none; }
        .ip-detail-grid { grid-template-columns: minmax(0, 1fr); padding: 16px 12px 20px; gap: 12px; }
        .ip-detail-section { padding: 16px; }
        .ip-detail-section-wide .ip-detail-rows { display: block; }
        .ip-detail-section-wide .ip-detail-row:nth-child(2) { border-top: 1px solid var(--detail-line); }
        .ip-detail-row { grid-template-columns: 96px minmax(0, 1fr); }
        .ip-detail-footer { align-items: flex-start; padding: 12px 16px; }
        .ip-detail-footer > svg { margin-top: 3px; }
      }
      button,
      a {
        -webkit-tap-highlight-color: transparent;
      }
      button:focus-visible,
      a:focus-visible {
        outline: none;
        box-shadow: 0 0 0 4px rgba(107, 124, 255, 0.18);
      }
      ::-webkit-scrollbar { width: 8px; height: 8px; }
      ::-webkit-scrollbar-track { background: transparent; }
      ::-webkit-scrollbar-thumb { background: #94a3b8; border-radius: 4px; }
      ::-webkit-scrollbar-thumb:hover { background: #64748b; }
      .dark ::-webkit-scrollbar-thumb { background: #475569; }
      .dark ::-webkit-scrollbar-thumb:hover { background: #93c5fd; }
      @media (prefers-reduced-motion: reduce) {
        *, *::before, *::after {
          animation-duration: 0.01ms !important;
          animation-iteration-count: 1 !important;
          transition-duration: 0.01ms !important;
          scroll-behavior: auto !important;
        }
      }
    </style>
  </head>
  <body>
    <div id="root"></div>

    <!-- 应用程序逻辑 -->
    <script type="text/babel" data-presets="react">
      const { useState, useEffect, useCallback, useRef } = React;
      const { createRoot } = ReactDOM;

      // 简化图标实现，避免依赖 lucide-react
      const ShieldCheck = () => <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"></path><path d="m9 12 2 2 4-4"></path></svg>;
      const Github = () => <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5.08-1.25-.27-2.48-1-3.5.28-1.15.28-2.35 0-3.5 0 0-1 0-3 1.5-2.64-.5-5.36-.5-8 0C6 2 5 2 5 2c-.3 1.15-.3 2.35 0 3.5A5.403 5.403 0 0 0 4 9c0 3.5 3 5.5 6 5.5-.39.49-.68 1.05-.85 1.65-.17.6-.22 1.23-.15 1.85v4"></path><path d="M9 18c-4.51 2-5-2-7-2"></path></svg>;
      const Globe = () => <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"></circle><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path><path d="M2 12h20"></path></svg>;
      // 太阳图标（白天模式）
      const Sun = () => <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>;
      // 月亮图标（夜间模式）
      const Moon = () => <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>;

      const RefreshCcw = () => <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 2v6h6"></path><path d="M21 12A9 9 0 0 0 6 5.3L3 8"></path><path d="M21 22v-6h-6"></path><path d="M3 12a9 9 0 0 0 15 6.7l3-2.7"></path></svg>;
      const ExternalLink = ({ className = 'w-4 h-4' }) => <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" className={className} stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/></svg>;
      // WiFi 图标（WebRTC 探测）
      const Wifi = () => <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 20h.01"></path><path d="M2 8.82a15 15 0 0 1 20 0"></path><path d="M5 12.859a10 10 0 0 1 14 0"></path><path d="M8.5 16.429a5 5 0 0 1 7 0"></path></svg>;
      const X = () => <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M18 6 6 18"></path><path d="m6 6 12 12"></path></svg>;
      const Shield = () => <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"></path></svg>;
      const Server = () => <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect><rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect><line x1="6" x2="6" y1="6" y2="6"></line><line x1="6" x2="6" y1="18" y2="18"></line></svg>;
      const Activity = () => <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"></path></svg>;
      const MapPin = () => <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M20 10c0 6-8 12-8 12s-8-6-8-12a8 8 0 0 1 16 0Z"></path><circle cx="12" cy="10" r="3"></circle></svg>;
      const AlertTriangle = () => <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" x2="12" y1="9" y2="13"></line><line x1="12" x2="12.01" y1="17" y2="17"></line></svg>;
      const CheckCircle2 = () => <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>;
      const Info = () => <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"></circle><path d="M12 16v-4"></path><path d="M12 8h.01"></path></svg>;

      // --- 图标 Data URIs (内嵌 SVG) ---
      const ICONS = {
        cloudflare: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 48 48'%3E%3Cpath fill='%23F48120' d='M35.1 14.8c-1.1 0-2.1.3-3.1.8-1.4-5.2-6.2-9-11.8-9-5.9 0-10.9 4.2-12.1 9.8C3.5 17 0 21.6 0 27s3.5 10 8.1 10.5h26.8c7.2 0 13.1-5.9 13.1-13.1 0-5.2-3-9.7-7.5-11.9-.6.2-1.1.3-1.7.3z'/%3E%3Cpath fill='%23F48120' d='M28.8 13.8c.8 0 1.6.1 2.3.4C29.7 9.9 25.4 6.8 20.2 6.8c-5.5 0-10.1 3.6-11.6 8.6 2.8-.8 5.8-1.3 9-1.3 4.2-.1 8.2.9 11.2 2.7z'/%3E%3C/svg%3E",
        bytedance: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 48 48'%3E%3Crect width='48' height='48' rx='12' fill='%23f8fafc'/%3E%3Cpath d='M10 15h6v22h-6z' fill='%234f46e5'/%3E%3Cpath d='M21 22h6v15h-6z' fill='%2306b6d4'/%3E%3Cpath d='M32 11h6v26h-6z' fill='%235eead4'/%3E%3C/svg%3E",
        github: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%2324292f'%3E%3Cpath d='M12 .5A12 12 0 0 0 8.2 23.9c.6.1.8-.2.8-.6v-2.1c-3.3.7-4-1.4-4-1.4-.6-1.4-1.4-1.8-1.4-1.8-1.1-.8.1-.8.1-.8 1.2.1 1.9 1.3 1.9 1.3 1.1 1.9 2.9 1.3 3.5 1 .1-.8.4-1.3.8-1.6-2.6-.3-5.4-1.3-5.4-5.9 0-1.3.5-2.4 1.2-3.2-.1-.3-.5-1.6.1-3.2 0 0 1-.3 3.3 1.2a11.4 11.4 0 0 1 6 0c2.3-1.5 3.3-1.2 3.3-1.2.7 1.6.2 2.9.1 3.2.8.8 1.2 1.9 1.2 3.2 0 4.6-2.8 5.6-5.5 5.9.5.4.9 1.2.9 2.4v3.5c0 .3.2.7.8.6A12 12 0 0 0 12 .5z'/%3E%3C/svg%3E",
        youtube: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 48 48'%3E%3Crect x='4' y='12' width='40' height='24' rx='8' fill='%23ff0033'/%3E%3Cpath d='M21 18.5v11l10-5.5z' fill='white'/%3E%3C/svg%3E",
        wechat: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 48 48'%3E%3Cpath fill='%2317bf32' d='M21 10C11.6 10 4 16.1 4 23.6c0 4.2 2.4 7.9 6.1 10.4l-1.3 4.7 5.4-2.7c2.1.8 4.4 1.2 6.8 1.2 9.4 0 17-6.1 17-13.6S30.4 10 21 10z'/%3E%3Cpath fill='%23ffffff' d='M15.5 21.2a1.8 1.8 0 1 1 0-3.6 1.8 1.8 0 0 1 0 3.6zm11 0a1.8 1.8 0 1 1 0-3.6 1.8 1.8 0 0 1 0 3.6z'/%3E%3Cpath fill='%230fb02d' d='M31 21c7.2 0 13 4.7 13 10.4 0 3.1-1.7 5.9-4.4 7.8l1 3.6-4.1-2c-1.7.6-3.5.9-5.5.9-7.2 0-13-4.7-13-10.4S23.8 21 31 21z'/%3E%3Cpath fill='%23ffffff' d='M27.2 29.4a1.4 1.4 0 1 1 0-2.8 1.4 1.4 0 0 1 0 2.8zm8.1 0a1.4 1.4 0 1 1 0-2.8 1.4 1.4 0 0 1 0 2.8z'/%3E%3C/svg%3E",
        ipsb: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%232563eb' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Ccircle cx='12' cy='12' r='10'/%3E%3Cpath d='M2 12h20'/%3E%3Cpath d='M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z'/%3E%3C/svg%3E",
        chatgpt: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%2310a37f'%3E%3Cpath d='M22.2819 9.8211a5.9847 5.9847 0 0 0-.5157-4.9108 6.0462 6.0462 0 0 0-6.5098-2.9A6.0651 6.0651 0 0 0 4.9807 4.1818a5.9847 5.9847 0 0 0-3.9977 2.9 6.0462 6.0462 0 0 0 .7427 7.0966 5.98 5.98 0 0 0 .511 4.9107 6.0462 6.0462 0 0 0 6.5146 2.9001A5.9847 5.9847 0 0 0 13.2599 24a6.0557 6.0557 0 0 0 5.7718-4.2058 5.9894 5.9894 0 0 0 3.9977-2.9001 6.0557 6.0557 0 0 0-.7475-7.0729zm-9.022 12.6081a4.4755 4.4755 0 0 1-2.8764-1.0408l.1419-.0804 4.7783-2.7582a.7948.7948 0 0 0 .3927-.6813v-6.7369l2.02 1.1686a.071.071 0 0 1 .038.052v5.5826a4.504 4.504 0 0 1-4.4945 4.4944zm-9.6607-4.1254a4.4708 4.4708 0 0 1-.5346-3.0137l.142.0852 4.783 2.7582a.7712.7712 0 0 0 .7806 0l5.8428-3.3685v2.3324a.0804.0804 0 0 1-.0332.0615L9.74 19.9502a4.4992 4.4992 0 0 1-6.1408-1.6464zM2.3408 7.8956a4.485 4.485 0 0 1 2.3655-1.9728V11.6a.7664.7664 0 0 0 .3879.6765l5.8144 3.3543-2.0201 1.1685a.0757.0757 0 0 1-.071 0l-4.8303-2.7865A4.504 4.504 0 0 1 2.3408 7.872zm16.5963 3.8558L13.1038 8.3829a.071.071 0 0 1-.038-.052V2.7482a4.4992 4.4992 0 0 1 4.4945 4.4944v5.8403a.7853.7853 0 0 0-.3832-.6813l-.2399-.6498zM6.803 3.3029l2.0201-1.1685a.0757.0757 0 0 1 .071 0l4.8303 2.7865a4.504 4.504 0 0 1 2.1461 3.8257l-.1466-.0852-4.783-2.7629a.7759.7759 0 0 0-.7854 0L4.3126 9.267V6.9346a.0804.0804 0 0 1 .0332-.0615l4.9522-3.2902a4.485 4.485 0 0 1-2.495 3.72zm8.1174 9.3485a4.4992 4.4992 0 0 1-6.1408 1.6511l-.1466-.0852 4.783-2.7582a.7759.7759 0 0 0 .3927-.6813v-6.7369l2.0201-1.1685a.0757.0757 0 0 1 .071 0l4.8303 2.7865a4.504 4.504 0 0 1-2.1461 3.8257zM11.9996 11.9996a1.1685 1.1685 0 1 1 1.1685-1.1685 1.1685 1.1685 0 0 1-1.1685 1.1685z'/%3E%3C/svg%3E",
        xcom: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='black'%3E%3Cpath d='M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z'/%3E%3C/svg%3E",
        openai: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='black'%3E%3Cpath d='M22.2819 9.8211a5.9847 5.9847 0 0 0-.5157-4.9108 6.0462 6.0462 0 0 0-6.5098-2.9A6.0651 6.0651 0 0 0 4.9807 4.1818a5.9847 5.9847 0 0 0-3.9977 2.9 6.0462 6.0462 0 0 0 .7427 7.0966 5.98 5.98 0 0 0 .511 4.9107 6.0462 6.0462 0 0 0 6.5146 2.9001A5.9847 5.9847 0 0 0 13.2599 24a6.0557 6.0557 0 0 0 5.7718-4.2058 5.9894 5.9894 0 0 0 3.9977-2.9001 6.0557 6.0557 0 0 0-.7475-7.0729zm-9.022 12.6081a4.4755 4.4755 0 0 1-2.8764-1.0408l.1419-.0804 4.7783-2.7582a.7948.7948 0 0 0 .3927-.6813v-6.7369l2.02 1.1686a.071.071 0 0 1 .038.052v5.5826a4.504 4.504 0 0 1-4.4945 4.4944zm-9.6607-4.1254a4.4708 4.4708 0 0 1-.5346-3.0137l.142.0852 4.783 2.7582a.7712.7712 0 0 0 .7806 0l5.8428-3.3685v2.3324a.0804.0804 0 0 1-.0332.0615L9.74 19.9502a4.4992 4.4992 0 0 1-6.1408-1.6464zM2.3408 7.8956a4.485 4.485 0 0 1 2.3655-1.9728V11.6a.7664.7664 0 0 0 .3879.6765l5.8144 3.3543-2.0201 1.1685a.0757.0757 0 0 1-.071 0l-4.8303-2.7865A4.504 4.504 0 0 1 2.3408 7.872zm16.5963 3.8558L13.1038 8.3829v5.5826a4.504 4.504 0 0 1-4.4945 4.4944zM11.9996 11.9996a1.1685 1.1685 0 1 1 1.1685-1.1685 1.1685 1.1685 0 0 1-1.1685 1.1685z'/%3E%3C/svg%3E",
        grok: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 512 509.641' fill-rule='evenodd' clip-rule='evenodd'%3E%3Cpath d='M115.612 0h280.776C459.975 0 512 52.026 512 115.612v278.416c0 63.587-52.025 115.613-115.612 115.613H115.612C52.026 509.641 0 457.615 0 394.028V115.612C0 52.026 52.026 0 115.612 0z'/%3E%3Cpath fill='%23fff' d='M213.235 306.019l178.976-180.002v.169l51.695-51.763c-.924 1.32-1.86 2.605-2.785 3.89-39.281 54.164-58.46 80.649-43.07 146.922l-.09-.101c10.61 45.11-.744 95.137-37.398 131.836-46.216 46.306-120.167 56.611-181.063 14.928l42.462-19.675c38.863 15.278 81.392 8.57 111.947-22.03 30.566-30.6 37.432-75.159 22.065-112.252-2.92-7.025-11.67-8.795-17.792-4.263l-124.947 92.341zm-25.786 22.437l-.033.034L68.094 435.217c7.565-10.429 16.957-20.294 26.327-30.149 26.428-27.803 52.653-55.359 36.654-94.302-21.422-52.112-8.952-113.177 30.724-152.898 41.243-41.254 101.98-51.661 152.706-30.758 11.23 4.172 21.016 10.114 28.638 15.639l-42.359 19.584c-39.44-16.563-84.629-5.299-112.207 22.313-37.298 37.308-44.84 102.003-1.128 143.81z'/%3E%3C/svg%3E",
        ipapi: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%237c3aed' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Crect x='2' y='2' width='20' height='20' rx='5' ry='5'/%3E%3Cpath d='M12 12m-3 0a3 3 0 1 0 6 0a3 3 0 1 0 -6 0'/%3E%3C/svg%3E"
      };

      // --- 枚举与工具函数 ---
      function getFlagEmoji(countryCode) {
        if (!/^[A-Z]{2}$/i.test(String(countryCode || ''))) return '🏳️';
        const codePoints = countryCode
          .toUpperCase()
          .split('')
          .map((c) => 127397 + c.charCodeAt(0));
        return String.fromCodePoint(...codePoints);
      }

      function getTrustScoreColor(score) {
        if (typeof score !== 'number' || !Number.isFinite(score)) return 'text-slate-600 dark:text-slate-400';
        return score >= 75
          ? 'text-green-700 dark:text-green-400'
          : score >= 45
            ? 'text-yellow-800 dark:text-yellow-300'
            : 'text-red-600 dark:text-red-400';
      }

      // 格式化 IP 类型 (住宅/机房/商用)
      const IpTypeBadge = ({ type }) => {
        if (!type) return <span className="text-slate-400">未知</span>;
        const lowerType = type.toLowerCase();
        let label = type;
        let colorClass = 'text-slate-900 dark:text-slate-100 font-bold';

        if (lowerType === 'isp') {
            label = '住宅';
            colorClass = 'text-green-600 dark:text-green-300 font-bold';
        } else if (lowerType === 'hosting') {
            label = '机房';
            colorClass = 'text-slate-800 dark:text-slate-200 font-bold';
        } else if (lowerType === 'business') {
            label = '商用';
            colorClass = 'text-amber-600 dark:text-amber-300 font-bold';
        }

        return <span className={colorClass}>{label}</span>;
      };

      // --- 网络请求辅助函数 (超时控制) ---
      const fetchWithTimeout = async (url, options = {}, timeout = 8000) => {
        const controller = new AbortController();
        const id = setTimeout(() => controller.abort(), timeout);
        try {
          const response = await fetch(url, { ...options, signal: controller.signal });
          clearTimeout(id);
          return response;
        } catch (error) {
          clearTimeout(id);
          throw error;
        }
      };

      const LATENCY_TARGETS = [
        {
          id: 'bytedance',
          name: '字节跳动',
          countryCode: 'CN',
          icon: ICONS.bytedance,
          url: 'https://lf3-static.bytednsdoc.com/obj/eden-cn/uhbfnupkbps/toutiao_favicon.ico',
          probe: 'image',
          cacheBust: true,
          timeout: 5000,
        },
        {
          id: 'github',
          name: 'GitHub',
          countryCode: 'US',
          icon: ICONS.github,
          url: 'https://github.github.io/janky/images/bg_hr.png',
          probe: 'image',
          cacheBust: true,
          timeout: 5000,
        },
        {
          id: 'youtube',
          name: 'YouTube',
          countryCode: 'US',
          icon: ICONS.youtube,
          url: 'https://www.youtube.com/generate_204',
          timeout: 5000,
        },
        {
          id: 'wechat',
          name: '微信',
          countryCode: 'CN',
          icon: ICONS.wechat,
          url: 'https://res.wx.qq.com/a/wx_fed/assets/res/NTI4MWU5.ico',
          probe: 'image',
          cacheBust: true,
          timeout: 5000,
        },
      ];

      const CONNECTIVITY_SAMPLE_COUNT = 10;

      const createEmptyLatencyResults = () => LATENCY_TARGETS.map((target) => ({
        ...target,
        latency: null,
        status: 'pending',
        error: null,
        samples: Array.from({ length: CONNECTIVITY_SAMPLE_COUNT }, () => ({ status: 'pending', latency: null })),
        sampleIndex: 0,
        animationKey: target.id + '-pending',
      }));

      const appendCacheBust = (url) => {
        const nextUrl = new URL(url, window.location.href);
        nextUrl.searchParams.set('t', Date.now().toString());
        return nextUrl.toString();
      };

      const loadImageWithTimeout = (url, timeout = 5000) => new Promise((resolve, reject) => {
        const img = new Image();
        let timerId = null;

        const cleanup = () => {
          img.onload = null;
          img.onerror = null;
          if (timerId) clearTimeout(timerId);
        };

        img.onload = () => {
          cleanup();
          resolve();
        };

        img.onerror = () => {
          cleanup();
          reject(new Error('图片加载失败'));
        };

        timerId = setTimeout(() => {
          cleanup();
          reject(new DOMException('The operation was aborted.', 'AbortError'));
        }, timeout);

        img.referrerPolicy = 'no-referrer';
        img.decoding = 'async';
        img.src = url;
      });

      const measureLatencyTarget = async (target) => {
        const startedAt = performance.now();
        const requestUrl = target.cacheBust ? appendCacheBust(target.url) : target.url;
        try {
          if (target.probe === 'image') {
            await loadImageWithTimeout(requestUrl, target.timeout);
          } else {
            await fetchWithTimeout(requestUrl, {
              method: target.method || 'GET',
              mode: 'no-cors',
              cache: 'no-store',
              credentials: 'omit',
              referrerPolicy: 'no-referrer',
            }, target.timeout);
          }

          return {
            latency: Math.max(1, Math.round(performance.now() - startedAt)),
            status: 'ok',
            error: null,
          };
        } catch (err) {
          return {
            latency: null,
            status: 'timeout',
            error: err?.name === 'AbortError' ? '请求超时' : '连接失败',
          };
        }
      };

      const WEBRTC_PROVIDER_CONFIGS = [
        { id: 'google', title: 'Google', address: 'stun.l.google.com', stunUrl: 'stun:stun.l.google.com:19302' },
        { id: 'cloudflare', title: 'Cloudflare', address: 'stun.cloudflare.com', stunUrl: 'stun:stun.cloudflare.com' },
        { id: 'nextcloud', title: 'NextCloud', address: 'stun.nextcloud.com', stunUrl: 'stun:stun.nextcloud.com:443' },
        { id: 'miwifi', title: '小米路由器', address: 'stun.miwifi.com', stunUrl: 'stun:stun.miwifi.com' },
      ];

      const createEmptyWebRTCProviders = () => WEBRTC_PROVIDER_CONFIGS.map(({ id, title, address }) => ({
        id,
        title,
        address,
        ip: '-',
        countryCode: '',
        locationLabel: '-',
        error: null,
        supported: true,
      }));

      const createSourceErrorResult = (error) => ({
        ip: '-',
        isp: '-',
        countryCode: '',
        countryName: '未知位置',
        error,
      });

      const buildSourceSuccessResult = ({ ip, isp = '-', countryCode = '', countryName = '' }) => {
        if (!isValidIpAddress(ip)) return createSourceErrorResult('响应中缺少有效 IP');

        const normalizedCountryCode = normalizeCountryCode(countryCode);
        return {
          ip: normalizeTextValue(ip),
          isp: normalizeTextValue(isp) || '-',
          countryCode: normalizedCountryCode,
          countryName: normalizeTextValue(countryName) || normalizedCountryCode || '未知位置',
          error: undefined,
        };
      };

      const isSuccessfulRowResult = (row) => !row?.isLoading && !row?.error && isValidIpAddress(row?.ip);

      const isIPv4String = (ip) => isValidIPv4Address(ip);

      const isIPv6String = (ip) => isValidIPv6Address(ip);

      const isPrivateIPAddress = (ip) => {
        if (isIPv4String(ip)) {
          const [a, b] = ip.split('.').map(Number);
          if (a === 10) return true;
          if (a === 172 && b >= 16 && b <= 31) return true;
          if (a === 192 && b === 168) return true;
          if (a === 127) return true;
          if (a === 169 && b === 254) return true;
          if (a === 100 && b >= 64 && b <= 127) return true;
          return false;
        }

        if (isIPv6String(ip)) {
          const lower = ip.toLowerCase();
          return lower === '::1' || lower.startsWith('fe80:') || lower.startsWith('fc') || lower.startsWith('fd');
        }

        return false;
      };

      const normalizePublicIpCandidate = (rawIp) => {
        if (!rawIp) return null;
        const ip = String(rawIp).trim().replace(/^\[|\]$/g, '').split('%')[0];
        if (!isIPv4String(ip) && !isIPv6String(ip)) return null;
        if (isPrivateIPAddress(ip)) return null;
        return ip;
      };

      const getWebRTCCountryCode = (data) => normalizeCountryCode(data?.country_code);

      const getWebRTCRegionDisplay = (data) => {
        const countryCode = getWebRTCCountryCode(data);
        if (countryCode) {
          return {
            countryCode,
            locationLabel: countryCode,
          };
        }

        const fallbackLabel = [data?.country, data?.organization, data?.isp, data?.asn_organization].find(Boolean) || '-';
        return {
          countryCode: '',
          locationLabel: fallbackLabel,
        };
      };

      const detectWebRTCByProvider = (provider) => {
        return new Promise((resolve) => {
          const RTCPeer = window.RTCPeerConnection || window.webkitRTCPeerConnection || window.mozRTCPeerConnection;
          if (!RTCPeer) {
            resolve({ ...provider, ip: '-', countryCode: '', locationLabel: '-', error: '浏览器不支持 WebRTC', supported: false });
            return;
          }

          const publicIPs = new Set();
          let resolved = false;
          let errorMessage = null;
          let pc = null;

          const finish = () => {
            if (resolved) return;
            resolved = true;

            const sdp = pc?.localDescription?.sdp || '';
            const candidateLines = sdp.match(/^a=candidate:.*$/gm) || [];
            candidateLines.forEach((line) => {
              const parts = line.trim().split(/\s+/);
              const typIndex = parts.indexOf('typ');
              const candidateType = typIndex !== -1 ? parts[typIndex + 1] : '';
              if (parts[4]) collectCandidate(parts[4], candidateType);
            });

            if (pc) {
              try {
                pc.onicecandidate = null;
                pc.onicecandidateerror = null;
                pc.onicegatheringstatechange = null;
                pc.close();
              } catch (e) {}
            }

            const ip = [...publicIPs][0] || '-';
            resolve({
              ...provider,
              ip,
              countryCode: '',
              locationLabel: '-',
              error: ip !== '-' ? null : (errorMessage || '未检测到 IP'),
              supported: true,
            });
          };

          const collectCandidate = (rawIp, candidateType) => {
            const ip = normalizePublicIpCandidate(rawIp);
            if (!ip) return;
            if (candidateType && !['host', 'srflx', 'relay', 'prflx'].includes(candidateType)) return;
            publicIPs.add(ip);
          };

          try {
            pc = new RTCPeer({
              iceServers: [{ urls: provider.stunUrl }],
            });

            pc.onicecandidate = (event) => {
              if (!event.candidate) {
                finish();
                return;
              }

              const candidateLine = event.candidate.candidate || '';
              const parts = candidateLine.trim().split(/\s+/);
              const typIndex = parts.indexOf('typ');
              const candidateType = event.candidate.type || (typIndex !== -1 ? parts[typIndex + 1] : '');

              collectCandidate(event.candidate.address, candidateType);
              if (parts[4]) collectCandidate(parts[4], candidateType);
            };

            pc.onicecandidateerror = (event) => {
              errorMessage = event?.errorText || 'STUN 节点无响应';
            };

            pc.onicegatheringstatechange = () => {
              if (pc.iceGatheringState === 'complete') {
                finish();
              }
            };

            pc.createDataChannel('probe');
            pc.createOffer()
              .then((offer) => pc.setLocalDescription(offer))
              .catch((err) => {
                errorMessage = err instanceof Error ? err.message : 'WebRTC 初始化失败';
                finish();
              });

            setTimeout(finish, 5000);
          } catch (err) {
            resolve({
              ...provider,
              ip: '-',
              countryCode: '',
              locationLabel: '-',
              error: err instanceof Error ? err.message : 'WebRTC 初始化失败',
              supported: false,
            });
          }
        });
      };

      const STYLE_PRESETS = [
        { id: 'linear', label: '冷峻', dotClass: 'bg-indigo-500' },
        { id: 'original', label: '原始', dotClass: 'bg-cyan-500' },
        { id: 'apple', label: 'Apple', dotClass: 'bg-sky-400' },
      ];
      const STYLE_PRESET_MAP = Object.fromEntries(STYLE_PRESETS.map((preset) => [preset.id, preset]));
      const DEFAULT_STYLE_PRESET = 'apple';
      const normalizeStylePreset = (value) => STYLE_PRESET_MAP[value] ? value : DEFAULT_STYLE_PRESET;
      const getNextStylePreset = (current) => {
        const index = STYLE_PRESETS.findIndex((preset) => preset.id === normalizeStylePreset(current));
        return STYLE_PRESETS[(index + 1) % STYLE_PRESETS.length].id;
      };
      const persistStylePreset = (value) => {
        const nextPreset = normalizeStylePreset(value);
        document.documentElement.dataset.style = nextPreset;
        localStorage.setItem('style-preset', nextPreset);
        return nextPreset;
      };

      // --- 主题切换组件 ---
      const StylePresetToggle = ({ value, onChange }) => {
        const currentPreset = STYLE_PRESET_MAP[normalizeStylePreset(value)];
        const cyclePreset = useCallback(() => {
          onChange(getNextStylePreset(value));
        }, [onChange, value]);

        return (
          <button
            onClick={cyclePreset}
            className="icon-button gap-2 px-3 py-2.5 text-slate-600 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white transition-all duration-200"
            aria-label={'切换界面风格，当前为 ' + currentPreset.label}
            title={'切换界面风格，当前为 ' + currentPreset.label}
          >
            <span className={'h-2 w-2 rounded-full ' + currentPreset.dotClass}></span>
            <span className="text-xs font-medium tracking-[0.02em]">{currentPreset.label}</span>
          </button>
        );
      };

      const ThemeToggle = () => {
        const [isDark, setIsDark] = useState(() => document.documentElement.classList.contains('dark'));

        const toggleTheme = useCallback(() => {
          const newDark = !isDark;
          setIsDark(newDark);
          if (newDark) {
            document.documentElement.classList.add('dark');
            localStorage.setItem('theme', 'dark');
          } else {
            document.documentElement.classList.remove('dark');
            localStorage.setItem('theme', 'light');
          }
        }, [isDark]);

        return (
          <button
            onClick={toggleTheme}
            className="icon-button p-2.5 text-slate-600 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white transition-all duration-200"
            aria-label={isDark ? '切换到白天模式' : '切换到夜间模式'}
            title={isDark ? '切换到白天模式' : '切换到夜间模式'}
          >
            {isDark ? <Sun /> : <Moon />}
          </button>
        );
      };

      // --- 组件 ---
      const SOURCE_TONE = {
        linear: {
          current: {
            badge: 'bg-slate-100 text-slate-700 dark:bg-slate-800/80 dark:text-slate-100',
            text: 'text-slate-900 dark:text-slate-50',
            glow: 'from-slate-300/10 via-indigo-400/8 to-transparent'
          },
          ipv4: {
            badge: 'bg-blue-50 text-blue-700 dark:bg-blue-950/40 dark:text-blue-200',
            text: 'text-blue-700 dark:text-blue-200',
            glow: 'from-blue-400/12 via-indigo-400/8 to-transparent'
          },
          ipv6: {
            badge: 'bg-indigo-50 text-indigo-700 dark:bg-indigo-950/40 dark:text-indigo-200',
            text: 'text-indigo-700 dark:text-indigo-200',
            glow: 'from-indigo-400/12 via-slate-300/8 to-transparent'
          },
          ipapi: {
            badge: 'bg-violet-50 text-violet-700 dark:bg-violet-950/40 dark:text-violet-200',
            text: 'text-violet-700 dark:text-violet-200',
            glow: 'from-violet-400/12 via-blue-400/8 to-transparent'
          },
          default: {
            badge: 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-200',
            text: 'text-slate-900 dark:text-slate-50',
            glow: 'from-slate-300/10 via-indigo-400/8 to-transparent'
          },
        },
        original: {
          current: {
            badge: 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/50 dark:text-cyan-200',
            text: 'text-cyan-700 dark:text-cyan-300',
            glow: 'from-cyan-500/30 to-sky-500/5'
          },
          ipv4: {
            badge: 'bg-sky-100 text-sky-700 dark:bg-sky-900/50 dark:text-sky-200',
            text: 'text-sky-700 dark:text-sky-300',
            glow: 'from-sky-500/30 to-blue-500/5'
          },
          ipv6: {
            badge: 'bg-blue-100 text-blue-700 dark:bg-blue-900/50 dark:text-blue-200',
            text: 'text-blue-700 dark:text-blue-300',
            glow: 'from-blue-500/30 to-indigo-500/5'
          },
          ipapi: {
            badge: 'bg-teal-100 text-teal-700 dark:bg-teal-900/50 dark:text-teal-200',
            text: 'text-teal-700 dark:text-teal-300',
            glow: 'from-teal-500/30 to-cyan-500/5'
          },
          default: {
            badge: 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-200',
            text: 'text-cyan-700 dark:text-cyan-300',
            glow: 'from-cyan-500/25 to-sky-500/5'
          },
        },
        apple: {
          current: {
            badge: 'bg-slate-100 text-slate-700 dark:bg-slate-800/80 dark:text-slate-100',
            text: 'text-slate-900 dark:text-slate-50',
            glow: 'from-slate-200/10 via-sky-300/8 to-transparent'
          },
          ipv4: {
            badge: 'bg-sky-50 text-sky-700 dark:bg-sky-950/40 dark:text-sky-200',
            text: 'text-sky-700 dark:text-sky-200',
            glow: 'from-sky-300/12 via-slate-300/8 to-transparent'
          },
          ipv6: {
            badge: 'bg-indigo-50 text-indigo-700 dark:bg-indigo-950/40 dark:text-indigo-200',
            text: 'text-indigo-700 dark:text-indigo-200',
            glow: 'from-indigo-300/12 via-slate-300/8 to-transparent'
          },
          ipapi: {
            badge: 'bg-slate-100 text-slate-700 dark:bg-slate-800/80 dark:text-slate-100',
            text: 'text-slate-800 dark:text-slate-100',
            glow: 'from-blue-300/12 via-slate-300/8 to-transparent'
          },
          default: {
            badge: 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-200',
            text: 'text-slate-900 dark:text-slate-50',
            glow: 'from-slate-200/10 via-sky-300/8 to-transparent'
          },
        },
      };

      const getSourceTone = (id, stylePreset = DEFAULT_STYLE_PRESET) => {
        const toneSet = SOURCE_TONE[normalizeStylePreset(stylePreset)] || SOURCE_TONE[DEFAULT_STYLE_PRESET];
        return toneSet[id] || toneSet.default;
      };

      const WEBRTC_TONE_SOURCE_MAP = {
        google: 'ipv4',
        cloudflare: 'current',
        nextcloud: 'ipapi',
        miwifi: 'ipv6',
      };

      const getWebRTCTone = (id, stylePreset = DEFAULT_STYLE_PRESET) => {
        return getSourceTone(WEBRTC_TONE_SOURCE_MAP[id] || 'default', stylePreset);
      };

      const isIPv6Address = (value) => typeof value === 'string' && value.includes(':');

      const splitIPv6ForDisplay = (ip) => {
        const value = String(ip || '');
        if (!value.includes(':')) return [value, ''];

        const middle = Math.floor(value.length / 2);
        let splitAt = value.indexOf(':', middle);
        if (splitAt <= 0 || splitAt >= value.length - 1) {
          splitAt = value.lastIndexOf(':', middle);
        }
        if (splitAt <= 0 || splitAt >= value.length - 1) {
          return [value, ''];
        }

        return [value.slice(0, splitAt + 1), value.slice(splitAt + 1)];
      };

      const CardIpText = ({ ip, toneText }) => {
        if (isIPv6Address(ip)) {
          const [line1, line2] = splitIPv6ForDisplay(ip);
          return (
            <div className={'h-12 px-1 ip-v6-wrap ' + toneText}>
              <div className="ip-v6-line text-[0.8rem] sm:text-[0.85rem] font-mono font-semibold">{line1}</div>
              <div className="ip-v6-line text-[0.8rem] sm:text-[0.85rem] font-mono font-semibold">{line2}</div>
            </div>
          );
        }

        return (
          <div className={'h-12 flex items-center justify-center ip-addr-inline text-xl sm:text-2xl font-mono font-bold ' + toneText}>
            {ip}
          </div>
        );
      };

      const SectionTitle = ({ icon: Icon, title }) => (
        <div className="ip-detail-section-title">
            <Icon />
            <h3>{title}</h3>
        </div>
      );

      const BoolBadge = ({ value, trueLabel = '是', falseLabel = '否' }) => {
        const label = value === undefined || value === null ? '未知' : value ? trueLabel : falseLabel;
        return <span className="ip-detail-badge">{label}</span>;
      };

      const RiskFlagBadge = ({ value }) => {
        if (value === true) {
          return <span className="ip-detail-badge ip-detail-badge-risk"><AlertTriangle />已检测到</span>;
        }
        if (value === false) {
          return <span className="ip-detail-badge ip-detail-badge-clear"><CheckCircle2 />未检测到</span>;
        }
        return <span className="ip-detail-badge" title="数据源未提供该项检测结果"><Info />暂无数据</span>;
      };

      const DetailRows = ({ rows }) => (
        <dl className="ip-detail-rows">
          {rows.map(([label, value]) => (
            <div key={label} className="ip-detail-row">
              <dt>{label}</dt>
              <dd>{value}</dd>
            </div>
          ))}
        </dl>
      );

      const DetailSection = ({ icon, title, rows, wide }) => {
        if (!rows.length) return null;
        return (
          <section className={'ip-detail-section' + (wide ? ' ip-detail-section-wide' : '')} aria-label={title}>
            <SectionTitle icon={icon} title={title} />
            <DetailRows rows={rows} />
          </section>
        );
      };

      const getCountryDisplayName = (value) => {
        const text = String(value || '').trim();
        if (!text) return '';
        const code = /^[A-Za-z]{2}$/.test(text) ? text.toUpperCase() : '';
        if (!code) return text;
        try {
          return new Intl.DisplayNames(['zh-CN'], { type: 'region' }).of(code) || code;
        } catch (error) {
          return code;
        }
      };

      const formatAddressCount = (value) => {
        if (typeof value === 'number' && Number.isFinite(value)) return value.toLocaleString('zh-CN');
        if (typeof value === 'string' && /^\d+$/.test(value)) {
          try {
            return BigInt(value).toLocaleString('zh-CN');
          } catch (error) {
            return value;
          }
        }
        return String(value);
      };

      const hasDetailValue = (value) => value !== undefined && value !== null && value !== '' && value !== '-' && value !== 'Unknown';

      const IpDetailModal = ({ isOpen, onClose, onRetry, selectedIp, data, loading, error }) => {
        const [clientTrustScore, setClientTrustScore] = useState(null);
        const [copyStatus, setCopyStatus] = useState('');
        const panelRef = useRef(null);
        const closeRef = useRef(null);
        const copyOperationRef = useRef(0);

        useEffect(() => {
          copyOperationRef.current += 1;
          setCopyStatus('');
          return () => { copyOperationRef.current += 1; };
        }, [isOpen, data?.ip]);

        // Worker 端请求 Net.Coffee 可能受出口限流影响；参考项目本身是浏览器直连，
        // 这里在服务端没有拿到 trust_score 时，用浏览器直连补一次评分。
        useEffect(() => {
          if (!isOpen || !data?.ip) {
            setClientTrustScore(null);
            return;
          }

          const serverScore = data.trust_score;
          if (typeof serverScore === 'number' && Number.isFinite(serverScore) && serverScore >= 0 && serverScore <= 100) {
            setClientTrustScore(null);
            return;
          }

          let cancelled = false;
          const controller = new AbortController();

          fetch('https://ip.net.coffee/api/ip/lookup/' + encodeURIComponent(data.ip), {
            headers: { Accept: 'application/json' },
            signal: controller.signal,
          })
            .then((response) => (response.ok ? response.json() : null))
            .then((payload) => {
              if (cancelled || !payload) return;
              if (!isSameIpAddress(payload.ip, data.ip)) return;
              const score = payload.trust_score;
              if (typeof score === 'number' && Number.isFinite(score) && score >= 0 && score <= 100) {
                setClientTrustScore(Math.round(score));
              }
            })
            .catch(() => {});

          return () => {
            cancelled = true;
            controller.abort();
          };
        }, [isOpen, data?.ip, data?.trust_score]);

        useEffect(() => {
          if (!isOpen) return;
          const previousFocus = document.activeElement;
          const previousOverflow = document.body.style.overflow;
          document.body.style.overflow = 'hidden';
          closeRef.current?.focus();
          const handleKeyDown = (e) => {
            if (e.key === 'Escape') onClose();
            if (e.key !== 'Tab') return;
            const targets = panelRef.current?.querySelectorAll('button:not(:disabled), a[href], [tabindex="0"]');
            if (!targets?.length) return;
            const first = targets[0];
            const last = targets[targets.length - 1];
            if (!Array.from(targets).includes(document.activeElement)) {
              e.preventDefault();
              (e.shiftKey ? last : first).focus();
              return;
            }
            if (e.shiftKey && document.activeElement === first) {
              e.preventDefault();
              last.focus();
            } else if (!e.shiftKey && document.activeElement === last) {
              e.preventDefault();
              first.focus();
            }
          };
          document.addEventListener('keydown', handleKeyDown);
          return () => {
            document.removeEventListener('keydown', handleKeyDown);
            document.body.style.overflow = previousOverflow;
            if (previousFocus?.isConnected) previousFocus.focus();
          };
        }, [isOpen, onClose]);

        useEffect(() => {
          if (isOpen && !panelRef.current?.contains(document.activeElement)) closeRef.current?.focus();
        }, [isOpen, loading, error, data?.ip]);

        if (!isOpen) return null;

        const handleBackdropClick = (e) => {
          if (e.target === e.currentTarget) onClose();
        };

        const handleCopy = async () => {
          const operation = ++copyOperationRef.current;
          setCopyStatus('复制中');
          try {
            await navigator.clipboard.writeText(data.ip);
            if (operation === copyOperationRef.current) setCopyStatus('已复制');
          } catch (error) {
            if (operation === copyOperationRef.current) setCopyStatus('复制失败，请手动选择 IP');
          }
        };

        let content;

        if (loading) {
          content = (
            <div className="ip-detail-state" role="status">
              <div className="ip-detail-state-icon"><span className="animate-spin"><RefreshCcw /></span></div>
              <h3>正在查询 IP 情报</h3>
              <p className="ip-detail-state-address">{selectedIp}</p>
              <p>正在汇总网络归属、地理位置与风险信息…</p>
            </div>
          );
        } else if (error) {
          content = (
            <div className="ip-detail-state" role="alert">
              <div className="ip-detail-state-icon"><AlertTriangle /></div>
              <h3>获取详情失败</h3>
              <p>{error}</p>
              <button onClick={onRetry} className="ip-detail-retry">重新获取</button>
            </div>
          );
        } else if (data) {
          const serverTrustScore =
            typeof data.trust_score === 'number' &&
            Number.isFinite(data.trust_score) &&
            data.trust_score >= 0 &&
            data.trust_score <= 100
              ? Math.round(data.trust_score)
              : null;
          const trustScore = serverTrustScore ?? clientTrustScore;
          const reputationLabel = trustScore === 100 ? '满分信誉' : 'IP 信誉分';
          const boolRow = (label, value) => (typeof value === 'boolean' ? [label, <BoolBadge value={value} />] : null);
          const riskFlagRow = (label, value) => [label, <RiskFlagBadge value={value} />];
          const formatRpkiStatus = (value) => {
            const key = String(value || '').toLowerCase();
            const labels = { valid: '有效', invalid: '无效', notfound: '未声明 ROA', unknown: '未知' };
            return labels[key] || String(value);
          };
          const registeredCountry = hasDetailValue(data.registered_country)
            ? data.registered_country
            : getCountryDisplayName(data.registered_country_code);
          const displayCountry = data.location?.country || getCountryDisplayName(data.location?.country_code);
          const companyName = data.company?.name || '';
          const serviceProvider = data.company?.isp || companyName;

          const networkRows = [
            hasDetailValue(registeredCountry) ? ['注册国家', registeredCountry] : null,
            boolRow('数据中心', data.is_datacenter),
            boolRow('移动网络', data.is_mobile),
            hasDetailValue(companyName) ? ['企业信息', companyName] : null,
            hasDetailValue(data.datacenter_name) ? ['机房名称', data.datacenter_name] : null,
          ].filter(Boolean);

          const asnRows = [
            hasDetailValue(data.asn?.asn) ? ['ASN', 'AS' + data.asn.asn] : null,
            hasDetailValue(serviceProvider) ? ['服务商', serviceProvider] : null,
            hasDetailValue(data.asn?.name) ? ['ASN 归属', data.asn.name] : null,
            hasDetailValue(data.asn?.org) ? ['ASN 组织', data.asn.org] : null,
            hasDetailValue(data.company?.network || data.asn?.route) ? ['CIDR', data.company?.network || data.asn?.route] : null,
            hasDetailValue(data.asn?.type) ? ['ASN 自报类型', <IpTypeBadge type={data.asn.type} />] : null,
            hasDetailValue(data.asn_ipv4_count) ? ['ASN IPv4 总量', formatAddressCount(data.asn_ipv4_count)] : null,
            hasDetailValue(data.asn_allocated) ? ['ASN 注册日期', data.asn_allocated] : null,
          ].filter(Boolean);

          const technicalRows = [
            ['地址类型', data.ip && data.ip.includes(':') ? 'IPv6' : 'IPv4'],
            hasDetailValue(data.range?.first) && hasDetailValue(data.range?.last) ? ['IP 范围', data.range.first + ' – ' + data.range.last] : null,
            hasDetailValue(data.range?.count) ? ['地址数量', formatAddressCount(data.range.count)] : null,
            hasDetailValue(data.asn_tbps) ? ['预估带宽', data.asn_tbps] : null,
            riskFlagRow('Bogon', data.is_bogon),
            riskFlagRow('Reddit 限制', data.reddit_blocked),
            hasDetailValue(data.ptr) ? ['PTR', data.ptr] : null,
            hasDetailValue(data.rpki_status) ? ['RPKI', formatRpkiStatus(data.rpki_status)] : null,
          ].filter(Boolean);

          const riskRows = [
            riskFlagRow('VPN', data.is_vpn),
            riskFlagRow('代理', data.is_proxy),
            riskFlagRow('Tor', data.is_tor),
            riskFlagRow('爬虫标记', data.is_crawler),
            riskFlagRow('滥用标记', data.is_abuser),
            hasDetailValue(data.abuse_score || data.company?.abuser_score || data.asn?.abuser_score)
              ? ['滥用评分', data.abuse_score || data.company?.abuser_score || data.asn?.abuser_score]
              : null,
          ].filter(Boolean);

          const locationRows = [
            hasDetailValue(data._source) ? ['数据来源', data._source] : null,
            hasDetailValue(displayCountry) ? ['国家 / 地区', displayCountry] : null,
            hasDetailValue(data.location?.state) ? ['地区', data.location.state] : null,
            hasDetailValue(data.location?.city) ? ['城市', data.location.city] : null,
            hasDetailValue(data.location?.latitude) ? ['纬度', data.location.latitude] : null,
            hasDetailValue(data.location?.longitude) ? ['经度', data.location.longitude] : null,
          ].filter(Boolean);

          const detailSections = [
            { icon: Activity, title: 'ASN / 运营商', rows: asnRows },
            { icon: ShieldCheck, title: '风险深度检测', rows: riskRows },
            { icon: Server, title: '网络属性', rows: networkRows },
            { icon: MapPin, title: '地理位置', rows: locationRows },
            { icon: Info, title: '技术指标', rows: technicalRows, wide: true },
          ].filter((section) => section.rows.length > 0);

          content = (
            <>
              <div className="ip-detail-overview">
                <div className="min-w-0">
                  <p className="ip-detail-address-label">IP 地址</p>
                  <h3 className="ip-detail-address">{data.ip?.split(':').map((part, index, parts) => <React.Fragment key={index}>{part + (index < parts.length - 1 ? ':' : '')}<wbr /></React.Fragment>)}</h3>
                  <div className="ip-detail-meta">
                    <MapPin />
                    <span>
                      {[displayCountry, data.location?.state, data.location?.city].filter(Boolean).filter((value, index, all) => all.indexOf(value) === index).join(' · ') || '未知位置'}
                    </span>
                  </div>
                  <div className="ip-detail-tags">
                    <span className="ip-detail-tag">{data.ip?.includes(':') ? 'IPv6' : 'IPv4'}</span>
                    {hasDetailValue(data.asn?.asn) && <span className="ip-detail-tag">{'AS' + data.asn.asn}</span>}
                    {hasDetailValue(data.rir) && <span className="ip-detail-tag">{data.rir}</span>}
                    <button className="ip-detail-copy" onClick={handleCopy} disabled={copyStatus === '复制中'} aria-label="复制 IP 地址">
                      {copyStatus === '已复制' ? <CheckCircle2 /> : <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></svg>}
                      {copyStatus === '已复制' ? '已复制' : '复制 IP'}
                    </button>
                    <span className={copyStatus === '已复制' ? 'sr-only' : 'ip-detail-copy-status'} role="status">{copyStatus}</span>
                  </div>
                </div>
                <div className={'ip-detail-score ' + getTrustScoreColor(trustScore)} aria-label={trustScore === null ? '信誉分未知' : 'IP 信誉分 ' + trustScore + ' / 100'}>
                  <div className="ip-detail-score-ring">
                    <svg viewBox="0 0 100 100" fill="none" aria-hidden="true">
                      <circle className="ip-detail-score-track" cx="50" cy="50" r="43" strokeWidth="5" />
                      {trustScore !== null && <circle cx="50" cy="50" r="43" stroke="currentColor" strokeWidth="5" strokeLinecap="round" pathLength="100" strokeDasharray={trustScore + ' 100'} />}
                    </svg>
                    <div className="ip-detail-score-value"><strong>{trustScore === null ? '—' : trustScore}</strong><small>/ 100</small></div>
                  </div>
                  <div className="ip-detail-score-caption">
                    <strong>{reputationLabel}</strong>
                    <p>{trustScore === null ? '数据源未提供评分' : '评分来源：Net.Coffee'}</p>
                  </div>
                </div>
              </div>
              <div className="ip-detail-grid">
                {detailSections.map((section) => (
                  <DetailSection key={section.title} {...section} />
                ))}
              </div>
            </>
          );
        } else {
          content = (
            <div className="ip-detail-state">
              <div className="ip-detail-state-icon"><Info /></div>
              <h3>暂无 IP 详情</h3>
              <p>暂时没有可展示的信息，请重新获取。</p>
              <button onClick={onRetry} className="ip-detail-retry">重新获取</button>
            </div>
          );
        }

        return (
          <div className="ip-detail-overlay">
            <div className="ip-detail-backdrop" onClick={handleBackdropClick} aria-hidden="true"></div>
            <div className="ip-detail-panel" ref={panelRef} role="dialog" aria-modal="true" aria-labelledby="ip-detail-title">
              <div className="ip-detail-toolbar">
                <div className="ip-detail-toolbar-title"><Globe /><h2 id="ip-detail-title">IP 详细信息</h2></div>
                <button ref={closeRef} onClick={onClose} className="ip-detail-close" aria-label="关闭详情"><X /></button>
              </div>
              <div className="ip-detail-body" tabIndex={0} aria-label="IP 详情内容" aria-busy={loading}>{content}</div>
              <div className="ip-detail-footer">
                <Info />
                <span>{data && !loading && !error ? '数据来源：' + (data._source || '未知') + '。暂无数据表示该项没有检测结果。' : 'IP 哨兵 · 多源网络身份分析'}</span>
              </div>
            </div>
          </div>
        );
      };

      const StatusCard = ({ data, onViewDetails, onRetry, stylePreset }) => {
        const { id, sourceName, sourceUrl, sourceIcon, ip, isp, countryCode, countryName, isLoading, error } = data;
        const tone = getSourceTone(id, stylePreset);
        const canViewDetails = !isLoading && !error && typeof onViewDetails === 'function' && isQueryableTarget(ip);

        return (
          <div className="status-card surface-card group rounded-2xl hover:-translate-y-1 transition-all duration-300 overflow-hidden flex flex-col relative">
            <div className={'absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity bg-gradient-to-br ' + tone.glow}></div>
            <div className="status-card__header relative p-4 border-b border-slate-200/70 dark:border-white/10 flex items-center justify-between">
              <div className="flex items-center gap-2">
                {sourceIcon ? (
                  <img src={sourceIcon} alt={sourceName} className="w-5 h-5 rounded-md object-cover" />
                ) : (
                  <div className={'w-5 h-5 rounded-md flex items-center justify-center font-bold text-xs ' + tone.badge}>
                    {sourceName.substring(0, 2).toUpperCase()}
                  </div>
                )}
                <h3 className="font-semibold tracking-[0.04em] text-slate-800 dark:text-slate-100 text-sm">{sourceName}</h3>
                <a
                  href={sourceUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  aria-label={sourceName + ' 外链'}
                  className="opacity-50 group-hover:opacity-100 ml-1 inline-flex items-center justify-center w-6 h-6 rounded-full text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white hover:bg-slate-100/70 dark:hover:bg-white/10 transition-all duration-300 hover:scale-110"
                >
                    <ExternalLink className="w-4 h-4 ml-0.5 mb-0.5" />
                </a>
              </div>
              {isLoading && <RefreshCcw className="w-4 h-4 text-cyan-500 animate-spin" />}
            </div>

            <div className="relative p-5 flex-1 flex flex-col justify-center">
              {error ? (
                <div className="text-center">
                  <p className="text-red-500 text-sm mb-2">{error}</p>
                  {onRetry && (
                      <button onClick={onRetry} className="text-xs text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200 underline">重试</button>
                  )}
                </div>
              ) : isLoading ? (
                <div className="space-y-3 animate-pulse">
                  <div className="h-6 bg-slate-100 dark:bg-slate-700 rounded w-3/4 mx-auto"></div>
                  <div className="h-4 bg-slate-100 dark:bg-slate-700 rounded w-1/2 mx-auto"></div>
                </div>
              ) : (
                <div className="text-center">
                  {canViewDetails ? (
                    <button
                      type="button"
                      aria-label={sourceName + ' 详情'}
                      className="group relative inline-block cursor-pointer bg-transparent border-0 p-0"
                      onClick={() => onViewDetails(ip)}
                    >
                      <div title={ip} className="ip-glow hover:text-slate-950 dark:hover:text-white transition-colors max-w-full">
                        <CardIpText ip={ip} toneText={tone.text} />
                      </div>
                      <div className="text-xs text-cyan-500 opacity-0 group-hover:opacity-100 transition-opacity absolute -bottom-4 left-1/2 transform -translate-x-1/2 whitespace-nowrap">点击查看详情</div>
                    </button>
                  ) : (
                    <div title={ip} className="ip-glow max-w-full">
                      <CardIpText ip={ip} toneText={tone.text} />
                    </div>
                  )}

                  <div className="mt-3 h-7 flex items-center justify-center gap-2 text-sm text-slate-600 dark:text-slate-300">
                      <span className="text-xl">{getFlagEmoji(countryCode)}</span>
                      <span className="font-medium">{countryName || '未知位置'}</span>
                  </div>

                  <div className="mt-1 h-7 flex items-center justify-center">
                    {isp && isp !== '-' ? (
                      <div className="subtle-pill text-xs text-slate-500 dark:text-slate-300 font-medium px-2.5 py-1 rounded-lg inline-block max-w-full truncate">
                        {isp}
                      </div>
                    ) : (
                      <div className="text-xs text-slate-300 dark:text-slate-600">-</div>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>
        );
      };

      const getLatencyDisplay = (latency, status) => {
        if (status === 'pending') {
          return {
            label: '检测中',
            text: 'text-slate-400 dark:text-slate-500',
          };
        }

        if (status !== 'ok' || typeof latency !== 'number') {
          return {
            label: '超时',
            text: 'text-rose-600 dark:text-rose-300',
          };
        }

        if (latency <= 80) {
          return {
            label: latency + 'ms',
            text: 'text-emerald-700 dark:text-emerald-300',
          };
        }

        if (latency <= 200) {
          return {
            label: latency + 'ms',
            text: 'text-green-600 dark:text-green-300',
          };
        }

        if (latency <= 500) {
          return {
            label: latency + 'ms',
            text: 'text-amber-600 dark:text-amber-300',
          };
        }

        return {
          label: latency + 'ms',
          text: 'text-rose-600 dark:text-rose-300',
        };
      };

      const getLatencyDotClass = (sample) => {
        if (!sample || sample.status === 'pending') return 'bg-slate-200 dark:bg-slate-700';
        if (sample.status !== 'ok' || typeof sample.latency !== 'number') return 'bg-rose-500 dark:bg-rose-400';
        if (sample.latency <= 200) return 'bg-green-600 dark:bg-green-400';
        if (sample.latency <= 500) return 'bg-amber-500 dark:bg-amber-400';
        return 'bg-rose-500 dark:bg-rose-400';
      };

      const ConnectivityCard = ({ item }) => {
        const display = getLatencyDisplay(item.latency, item.status);
        const flag = getFlagEmoji(item.countryCode);
        const sampleCount = Math.min(item.sampleIndex || 0, CONNECTIVITY_SAMPLE_COUNT);

        return (
          <div className="connectivity-card" title={item.name + ' ' + sampleCount + '/' + CONNECTIVITY_SAMPLE_COUNT + ' ' + display.label}>
            <img src={item.icon} alt={item.name} className="connectivity-icon" />
            <div className="connectivity-main">
              <span className="connectivity-name">
                {item.name}
                <span className="ml-1" title={item.countryCode}>{flag}</span>
              </span>
              <div className="connectivity-dots" aria-label={item.name + ' 连通性质量'}>
                {item.samples.map((sample, index) => (
                  <span
                    key={index}
                    className={'connectivity-dot ' + getLatencyDotClass(sample)}
                  ></span>
                ))}
              </div>
            </div>
            <div className={'connectivity-ms ' + display.text}>
              <span key={item.animationKey} className="connectivity-ms-value">
                {display.label}
              </span>
            </div>
          </div>
        );
      };

      const ConnectivitySection = ({ className = '', style = {} }) => {
        const [items, setItems] = useState(createEmptyLatencyResults);
        const mountedRef = useRef(true);

        useEffect(() => {
          mountedRef.current = true;
          let round = 0;
          let timeoutId = null;
          let cancelled = false;

          const applyRoundResults = (roundIndex, results) => {
            setItems((prev) => prev.map((item) => {
              const result = results.find((entry) => entry.id === item.id) || {
                latency: null,
                status: 'timeout',
                error: '连接失败',
              };
              const samples = item.samples.slice();
              samples[roundIndex] = {
                latency: result.latency,
                status: result.status,
              };
              const shouldUpdateDisplay = roundIndex + 1 >= (item.sampleIndex || 0);

              return {
                ...item,
                latency: shouldUpdateDisplay ? result.latency : item.latency,
                status: shouldUpdateDisplay ? result.status : item.status,
                error: shouldUpdateDisplay ? (result.error || null) : item.error,
                samples,
                sampleIndex: Math.max(item.sampleIndex || 0, roundIndex + 1),
                animationKey: shouldUpdateDisplay
                  ? item.id + '-' + roundIndex + '-' + (result.latency ?? result.status)
                  : item.animationKey,
              };
            }));
          };

          const scheduleNextRound = () => {
            if (cancelled || round >= CONNECTIVITY_SAMPLE_COUNT) return;
            timeoutId = setTimeout(runRound, 1000);
          };

          const runRound = () => {
            if (cancelled || round >= CONNECTIVITY_SAMPLE_COUNT) return;
            const roundIndex = round;
            round += 1;

            ipService.measureConnectivity()
              .then((results) => {
                if (!mountedRef.current || cancelled) return;
                applyRoundResults(roundIndex, results);
              })
              .catch(() => {
                if (!mountedRef.current || cancelled) return;
                applyRoundResults(roundIndex, LATENCY_TARGETS.map((target) => ({
                  ...target,
                  latency: null,
                  status: 'timeout',
                  error: '连接失败',
                })));
              })
              .finally(() => {
                if (!mountedRef.current || cancelled) return;
                scheduleNextRound();
              });
          };

          runRound();

          return () => {
            cancelled = true;
            mountedRef.current = false;
            clearTimeout(timeoutId);
          };
        }, []);

        return (
          <section className={'connectivity-section ' + className} style={style}>
            <div className="connectivity-panel">
              <div className="connectivity-grid">
                {items.map((item) => (
                  <ConnectivityCard key={item.id} item={item} />
                ))}
              </div>
            </div>
          </section>
        );
      };

      // --- 泄漏检测卡片组件 ---
      const LeakDetectionCard = ({ icon: Icon, title, subtitle = '', isLoading, status, statusText, showStatus = true, tone, bodyClassName = '', children }) => {
        const statusConfig = {
          safe: { badge: 'border border-emerald-200/70 bg-emerald-50/90 text-emerald-700 dark:border-emerald-900/40 dark:bg-emerald-950/30 dark:text-emerald-300' },
          leak: { badge: 'border border-rose-200/70 bg-rose-50/90 text-rose-700 dark:border-rose-900/40 dark:bg-rose-950/30 dark:text-rose-300' },
          unknown: { badge: 'border border-slate-200/70 bg-slate-100/90 text-slate-600 dark:border-slate-700 dark:bg-slate-800/90 dark:text-slate-300' },
          unsupported: { badge: 'border border-amber-200/70 bg-amber-50/90 text-amber-700 dark:border-amber-900/40 dark:bg-amber-950/30 dark:text-amber-300' },
        };
        const cfg = statusConfig[status] || statusConfig.unknown;
        const resolvedTone = tone || getSourceTone('default');

        return (
          <div className="status-card surface-card group rounded-2xl hover:-translate-y-1 transition-all duration-300 overflow-hidden flex flex-col relative">
            <div className={'absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity bg-gradient-to-br ' + resolvedTone.glow}></div>
            <div className="status-card__header relative p-4 border-b border-slate-200/70 dark:border-white/10 flex items-center justify-between gap-3">
              <div className="min-w-0 flex items-center gap-2">
                <div className={'w-8 h-8 rounded-xl flex items-center justify-center shrink-0 ' + resolvedTone.badge}>
                  <Icon className="w-4 h-4" />
                </div>
                <div className="min-w-0">
                  <h3 className="font-semibold tracking-[0.04em] text-slate-800 dark:text-slate-100 text-sm">{title}</h3>
                  {subtitle ? <div className="mt-0.5 text-[11px] font-mono text-slate-400 dark:text-slate-500 truncate">{subtitle}</div> : null}
                </div>
              </div>
              {isLoading ? (
                <RefreshCcw className={'w-4 h-4 animate-spin ' + resolvedTone.text} />
              ) : showStatus ? (
                <span className={'inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold whitespace-nowrap ' + cfg.badge}>
                  {statusText}
                </span>
              ) : null}
            </div>
            <div className={'relative p-5 flex-1 flex flex-col justify-center ' + bodyClassName}>
              {isLoading ? (
                <div className="text-center animate-pulse">
                  <div className="h-12 flex items-center justify-center">
                    <div className="h-6 bg-slate-100 dark:bg-slate-700 rounded w-3/4 mx-auto"></div>
                  </div>
                  <div className="mt-3 h-7 flex items-center justify-center">
                    <div className="h-4 bg-slate-100 dark:bg-slate-700 rounded w-14"></div>
                  </div>
                  <div className="mt-1 h-7 flex items-center justify-center">
                    <div className="h-6 bg-slate-100 dark:bg-slate-700 rounded-lg w-24"></div>
                  </div>
                </div>
              ) : children}
            </div>
          </div>
        );
      };

      const WebRTCProviderCard = ({ provider, isLoading, hasChecked, stylePreset }) => {
        const providerStatus = isLoading
          ? { status: 'unknown', text: '检测中...' }
          : hasChecked
            ? deriveWebRTCStatus(provider)
            : { status: 'unknown', text: '未开始' };
        const tone = getWebRTCTone(provider.id, stylePreset);

        return (
          <LeakDetectionCard
            icon={Wifi}
            title={provider.title}
            isLoading={isLoading}
            status={providerStatus.status}
            statusText={providerStatus.text}
            showStatus={true}
            tone={tone}
            bodyClassName="h-32"
          >
            {!hasChecked ? (
              <div className="text-center">
                <div className="h-12 flex items-center justify-center text-sm font-medium text-slate-500 dark:text-slate-400">
                  等待开始检测
                </div>
                <div className="mt-3 h-7 flex items-center justify-center text-xs text-slate-400 dark:text-slate-500">
                  点击上方按钮后显示结果
                </div>
                <div className="mt-1 h-7 flex items-center justify-center">
                  <div className="subtle-pill text-xs text-slate-500 dark:text-slate-300 font-medium px-2.5 py-1 rounded-lg inline-block max-w-full truncate">
                    {provider.address}
                  </div>
                </div>
              </div>
            ) : provider.error && (!provider.ip || provider.ip === '-') ? (
              <div className="text-center">
                <div className="mx-auto max-w-full rounded-xl border border-amber-200/70 bg-amber-50/80 px-3 py-2 text-sm font-medium text-amber-700 dark:border-amber-900/50 dark:bg-amber-900/20 dark:text-amber-300 break-words">
                  {provider.error}
                </div>
              </div>
            ) : (
              <div className="text-center">
                <div title={provider.ip || '-'} className="ip-glow max-w-full">
                  <CardIpText ip={provider.ip || '-'} toneText={tone.text} />
                </div>

                <div className="mt-3 h-7 flex items-center justify-center gap-2 text-sm text-slate-600 dark:text-slate-300">
                  {provider.countryCode ? (
                    <>
                      <span className="text-xl">{getFlagEmoji(provider.countryCode)}</span>
                      <span className="font-medium">{provider.countryCode}</span>
                    </>
                  ) : (
                    <>
                      <span className="text-xl">🏳️</span>
                      <span className="font-medium break-words">{provider.locationLabel || '-'}</span>
                    </>
                  )}
                </div>

                <div className="mt-1 h-7 flex items-center justify-center">
                  <div className="subtle-pill text-xs text-slate-500 dark:text-slate-300 font-medium px-2.5 py-1 rounded-lg inline-block max-w-full truncate">
                    {provider.address}
                  </div>
                </div>
              </div>
            )}
          </LeakDetectionCard>
        );
      };

      // --- 泄漏检测区域 ---
      const LeakDetectionSection = ({ stylePreset }) => {
        const [webrtc, setWebrtc] = useState({ loading: false, providers: createEmptyWebRTCProviders(), error: null });
        const [lastCheckedAt, setLastCheckedAt] = useState(null);
        const mountedRef = useRef(true);

        const runLeakChecks = useCallback(() => {
          setWebrtc({ loading: true, providers: createEmptyWebRTCProviders(), error: null });

          ipService.detectWebRTC()
            .then(result => {
              if (!mountedRef.current) return;
              setWebrtc({ loading: false, providers: result.providers, error: result.error || null });
              setLastCheckedAt(new Date());
            })
            .catch((err) => {
              if (!mountedRef.current) return;
              setWebrtc({
                loading: false,
                providers: createEmptyWebRTCProviders().map((provider) => ({
                  ...provider,
                  supported: false,
                  error: err instanceof Error ? err.message : 'WebRTC 检测失败',
                })),
                error: err instanceof Error ? err.message : 'WebRTC 检测失败',
              });
              setLastCheckedAt(new Date());
            });
        }, []);

        useEffect(() => {
          return () => {
            mountedRef.current = false;
          };
        }, []);

        const hasChecked = Boolean(lastCheckedAt);
        const buttonText = webrtc.loading ? '检测中' : (hasChecked ? '重新检测' : '开始检测');

        return (
          <div className="mt-10">
            <div className="mb-6 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
              <div className="text-center md:text-left">
                <h2 className="text-xl font-bold text-slate-800 dark:text-slate-100 mb-1 flex items-center gap-2 justify-center md:justify-start">
                  <Shield className="w-5 h-5 text-indigo-600 dark:text-indigo-400" />
                  WebRTC IP检测
                </h2>
                <p className="text-slate-500 dark:text-slate-400 text-sm">
                  基于不同 STUN 节点检测公网出口 IP 与区域信息
                </p>
              </div>
              <div className="flex justify-center md:justify-end">
                <div className="flex flex-col items-center md:items-end gap-1">
                  <button
                    type="button"
                    onClick={runLeakChecks}
                    disabled={webrtc.loading}
                    className="action-button inline-flex items-center gap-2 px-3.5 py-2 rounded-xl text-sm font-medium text-slate-700 dark:text-slate-200 disabled:opacity-60 disabled:cursor-not-allowed transition"
                  >
                    <RefreshCcw className={'w-4 h-4 ' + (webrtc.loading ? 'animate-spin text-indigo-500' : 'text-slate-500')} />
                    {buttonText}
                  </button>
                  {lastCheckedAt ? (
                    <span className="text-xs text-slate-400 dark:text-slate-500">
                      {'上次检测: ' + lastCheckedAt.toLocaleTimeString('zh-CN', { hour12: false })}
                    </span>
                  ) : null}
                </div>
              </div>
            </div>

              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6">
                {webrtc.providers.map((provider) => (
                <WebRTCProviderCard key={provider.id} provider={provider} isLoading={webrtc.loading} hasChecked={hasChecked} stylePreset={stylePreset} />
                ))}
              </div>
          </div>
        );
      };

      // --- Cloudflare Trace 通用请求工厂（消除重复代码）---
      const createTraceFetcher = (url) => async () => {
        try {
          const res = await fetchWithTimeout(url);
          if (!res.ok) throw new Error('网络响应错误');
          const text = await res.text();
          const parsed = parseTraceResponse(text);
          return parsed.error ? createSourceErrorResult(parsed.error) : { ...parsed, isp: '-' };
        } catch (e) {
          return createSourceErrorResult('连接超时或被拦截');
        }
      };

      // --- 客户端 IP 数据源（参考 one-ip 的多源回退）---
      const IP_ECHO_TIMEOUT = 5000;

      const requestJson = async (url, timeout = IP_ECHO_TIMEOUT) => {
        const res = await fetchWithTimeout(url, { cache: 'no-store', credentials: 'omit' }, timeout);
        if (!res.ok) throw new Error('HTTP ' + res.status);
        return await res.json();
      };

      const requestText = async (url, timeout = IP_ECHO_TIMEOUT) => {
        const res = await fetchWithTimeout(url, { cache: 'no-store', credentials: 'omit' }, timeout);
        if (!res.ok) throw new Error('HTTP ' + res.status);
        return (await res.text()).trim();
      };

      const canonicalizeIpAddress = (ip) => {
        if (isValidIPv4Address(ip)) return normalizeTextValue(ip);
        if (!isValidIPv6Address(ip)) return '';
        try {
          return new URL(\`http://[\${ip}]/\`).hostname.slice(1, -1);
        } catch (e) {
          return normalizeTextValue(ip).toLowerCase();
        }
      };

      const isSameIpAddress = (left, right) => {
        const leftValue = canonicalizeIpAddress(left);
        return Boolean(leftValue) && leftValue === canonicalizeIpAddress(right);
      };

      const lookupGeoByIpwho = async (ip) => {
        const data = await requestJson(\`https://ipwho.is/\${encodeURIComponent(ip)}\`);
        if (data?.success !== true || !isSameIpAddress(data.ip, ip)) throw new Error('ipwho.is 未返回有效结果');
        return {
          ip,
          isp: data.connection?.isp || data.connection?.org || '-',
          countryCode: data.country_code,
          countryName: data.country,
        };
      };

      const lookupGeoByIpapi = async (ip) => {
        const data = await requestJson(\`https://api.ipapi.is?q=\${encodeURIComponent(ip)}\`);
        if (!isSameIpAddress(data?.ip, ip)) throw new Error('ipapi.is 未返回有效结果');
        return {
          ip,
          isp: (typeof data.asn === 'string' ? data.asn : data.asn?.org) || data.company || '-',
          countryCode: data.country_code || data.location?.country_code,
          countryName: data.country || data.location?.country,
        };
      };

      const lookupGeoByIpinfo = async (ip) => {
        const data = await requestJson(\`https://ipinfo.io/\${encodeURIComponent(ip)}/json\`);
        if (!isSameIpAddress(data?.ip, ip)) throw new Error('ipinfo.io 未返回有效结果');
        return {
          ip,
          isp: data.org || '-',
          countryCode: data.country,
          countryName: data.country,
        };
      };

      const geoLookupCache = new Map();

      const fetchGeoByIp = async (ip) => {
        if (geoLookupCache.has(ip)) return geoLookupCache.get(ip);

        const sources = [lookupGeoByIpwho, lookupGeoByIpapi, lookupGeoByIpinfo];
        for (const source of sources) {
          try {
            const result = await source(ip);
            geoLookupCache.set(ip, result);
            if (geoLookupCache.size > 30) {
              geoLookupCache.delete(geoLookupCache.keys().next().value);
            }
            return result;
          } catch (e) {
            // 继续尝试下一个数据源
          }
        }
        return { ip, isp: '-', countryCode: '', countryName: '未知位置' };
      };

      const readMyIpWtf = async (url) => (await requestJson(url)).YourFuckingIPAddress;

      const IPV4_ECHO_SOURCES = [
        { name: 'icanhazip', read: () => requestText('https://ipv4.icanhazip.com') },
        { name: 'myip.wtf', read: () => readMyIpWtf('https://ipv4.myip.wtf/json') },
        { name: 'ipify', read: async () => (await requestJson('https://api.ipify.org?format=json')).ip },
      ];

      const IPV6_ECHO_SOURCES = [
        { name: 'myip.wtf', read: () => readMyIpWtf('https://ipv6.myip.wtf/json') },
        { name: 'ident.me', read: () => requestText('https://v6.ident.me') },
        { name: 'ipify', read: async () => (await requestJson('https://api6.ipify.org?format=json')).ip },
        { name: 'icanhazip', read: () => requestText('https://ipv6.icanhazip.com') },
      ];

      const resolveEgressIp = async (version) => {
        const sources = version === 6 ? IPV6_ECHO_SOURCES : IPV4_ECHO_SOURCES;
        let sawCandidate = false;

        for (const source of sources) {
          try {
            const candidate = normalizeTextValue(await source.read());
            if (!candidate) continue;
            sawCandidate = true;
            const matchesVersion = version === 6 ? isValidIPv6Address(candidate) : isValidIPv4Address(candidate);
            if (!matchesVersion) continue;
            const geo = await fetchGeoByIp(candidate);
            return buildSourceSuccessResult({
              ip: candidate,
              isp: geo.isp,
              countryCode: geo.countryCode,
              countryName: geo.countryName,
            });
          } catch (e) {
            // 继续尝试下一个数据源
          }
        }

        return createSourceErrorResult(sawCandidate ? \`未检测到 IPv\${version} 出口\` : '加载失败');
      };

      // --- 数据服务层 (客户端直接请求) ---
      const ipService = {
        measureConnectivity: async () => {
          return await Promise.all(
            LATENCY_TARGETS.map(async (target) => ({
              ...target,
              ...(await measureLatencyTarget(target)),
            }))
          );
        },
        fetchChatGPT: createTraceFetcher('https://chatgpt.com/cdn-cgi/trace'),
        fetchXcom: createTraceFetcher('https://help.x.com/cdn-cgi/trace'),
        fetchOpenAI: createTraceFetcher('https://openai.com/cdn-cgi/trace'),
        fetchGrok: createTraceFetcher('https://grok.com/cdn-cgi/trace'),
        // IPv4 / IPv6 出口（ip.sb 已不可用，改用多源回退）
        fetchIpv4: () => resolveEgressIp(4),
        fetchIpv6: () => resolveEgressIp(6),
        // 当前 IP 基础信息（ipwho.is 主源，ipapi.is / ipinfo.io 回退）
        fetchIpApi: async () => {
          const sources = [
            {
              name: 'ipwho.is',
              url: 'https://ipwho.is',
              load: async () => {
                const data = await requestJson('https://ipwho.is/');
                if (data?.success !== true || !isValidIpAddress(data.ip)) throw new Error('invalid');
                return {
                  ip: data.ip,
                  isp: data.connection?.isp || data.connection?.org,
                  countryCode: data.country_code,
                  countryName: data.country,
                };
              },
            },
            {
              name: 'IPAPI.is',
              url: 'https://ipapi.is',
              load: async () => {
                const data = await requestJson('https://api.ipapi.is/');
                if (!isValidIpAddress(data?.ip)) throw new Error('invalid');
                return {
                  ip: data.ip,
                  isp: (typeof data.asn === 'string' ? data.asn : data.asn?.org) || data.company,
                  countryCode: data.country_code,
                  countryName: data.country,
                };
              },
            },
            {
              name: 'ipinfo.io',
              url: 'https://ipinfo.io',
              load: async () => {
                const data = await requestJson('https://ipinfo.io/json');
                if (!isValidIpAddress(data?.ip)) throw new Error('invalid');
                return {
                  ip: data.ip,
                  isp: data.org,
                  countryCode: data.country,
                  countryName: data.country,
                };
              },
            },
          ];

          for (const source of sources) {
            try {
              const result = await source.load();
              return {
                ...buildSourceSuccessResult(result),
                sourceName: source.name,
                sourceUrl: source.url,
              };
            } catch (e) {
              // 继续尝试下一个数据源
            }
          }

          return createSourceErrorResult('加载失败');
        },
        // 详情查询 (使用 Worker 中转，后端多源回退)
        fetchIpDetails: async (ip) => {
          if (!isQueryableTarget(ip)) throw new Error('详情查询目标无效');
          const res = await fetchWithTimeout(\`/api/ipapi?q=\${encodeURIComponent(ip)}\`);
          if (!res.ok) throw new Error('详情查询失败');
          return await res.json();
        },
        // WebRTC 区域信息（ipwho.is 主源）
        fetchWebRTCRegion: async (ip) => {
          const geo = await fetchGeoByIp(ip);
          return {
            country_code: geo.countryCode,
            country: geo.countryName,
            organization: geo.isp,
            isp: geo.isp,
          };
        },

        // --- WebRTC IP 检测 ---
        detectWebRTC: async () => {
          const providers = await Promise.all(WEBRTC_PROVIDER_CONFIGS.map((provider) => detectWebRTCByProvider(provider)));

          const enrichedProviders = await Promise.all(
            providers.map(async (provider) => {
              if (!isValidIpAddress(provider.ip)) return provider;

              try {
                const details = await ipService.fetchWebRTCRegion(provider.ip);
                return {
                  ...provider,
                  ...getWebRTCRegionDisplay(details),
                };
              } catch (err) {
                return {
                  ...provider,
                  countryCode: '',
                  locationLabel: '-',
                };
              }
            })
          );

          const errorCount = enrichedProviders.filter((provider) => provider.error && provider.ip === '-').length;
          const summaryError = errorCount === enrichedProviders.length ? '所有 WebRTC 节点均未检测到结果' : null;

          return { providers: enrichedProviders, error: summaryError };
        }
      };

      // id → 请求函数映射（用于 loadData 和 onRetry 共用）
      const FETCH_MAP = {
        ipv4: () => ipService.fetchIpv4(),
        ipv6: () => ipService.fetchIpv6(),
        ipapi: () => ipService.fetchIpApi(),
        chatgpt: () => ipService.fetchChatGPT(),
        xcom: () => ipService.fetchXcom(),
        openai: () => ipService.fetchOpenAI(),
        grok: () => ipService.fetchGrok(),
      };

      // 数据源卡片配置（配置驱动，消除重复模板代码）
      const SOURCE_CONFIGS = [
        { id: 'ipv4', sourceName: 'IPv4 出口', sourceUrl: 'https://ipwho.is', sourceIcon: ICONS.ipsb, isp: '...' },
        { id: 'ipv6', sourceName: 'IPv6 出口', sourceUrl: 'https://ipwho.is', sourceIcon: ICONS.ipsb, isp: '...' },
        { id: 'ipapi', sourceName: 'ipwho.is', sourceUrl: 'https://ipwho.is', sourceIcon: ICONS.ipapi, isp: '...' },
        { id: 'chatgpt', sourceName: 'chatgpt.com', sourceUrl: 'https://chatgpt.com', sourceIcon: ICONS.chatgpt },
				{ id: 'openai', sourceName: 'openai.com', sourceUrl: 'https://openai.com', sourceIcon: ICONS.openai },
        { id: 'xcom', sourceName: 'X.com', sourceUrl: 'https://x.com', sourceIcon: ICONS.xcom },
        { id: 'grok', sourceName: 'grok.com', sourceUrl: 'https://grok.com', sourceIcon: ICONS.grok },
      ];

      const App = () => {
        // 使用服务端注入的 Cloudflare 数据初始化第一张卡片，其余卡片通过配置生成
        const [rows, setRows] = useState([
          {
            id: 'current',
            sourceName: '当前连接 (Worker)',
            sourceUrl: 'https://cloudflare.com',
            sourceIcon: ICONS.cloudflare,
            ip: window.CF_DATA.ip,
            isp: window.CF_DATA.isp,
            countryCode: normalizeCountryCode(window.CF_DATA.country),
            countryName: normalizeCountryCode(window.CF_DATA.country) || '未知位置',
            isLoading: false,
          },
          ...SOURCE_CONFIGS.map(({ id, sourceName, sourceUrl, sourceIcon, isp }) => ({
            id, sourceName, sourceUrl, sourceIcon,
            ip: '加载中...', isp: isp || '-', countryCode: '', countryName: '...', isLoading: true,
          })),
        ]);

        const [modalOpen, setModalOpen] = useState(false);
        const [selectedIp, setSelectedIp] = useState(null);
        const [detailData, setDetailData] = useState(null);
        const [detailLoading, setDetailLoading] = useState(false);
        const [detailError, setDetailError] = useState(null);
        const [stylePreset, setStylePreset] = useState(() => normalizeStylePreset(document.documentElement.dataset.style || localStorage.getItem('style-preset')));
        const handleCloseModal = useCallback(() => setModalOpen(false), []);

        const updateRow = useCallback((id, data) => {
          setRows((prev) => prev.map((row) => (row.id === id ? { ...row, ...data, isLoading: false } : row)));
        }, []);

        const loadData = useCallback(() => {
          // 不重新加载 'current'，因为它来自服务端注入，永远是准确的 Inbound IP
          Object.entries(FETCH_MAP).forEach(([id, fetchFn]) => {
            fetchFn().then((data) => updateRow(id, data));
          });
        }, [updateRow]);

        useEffect(() => {
          loadData();
        }, [loadData]);

        useEffect(() => {
          persistStylePreset(stylePreset);
        }, [stylePreset]);

        const handleViewDetails = async (ip) => {
          if (!isQueryableTarget(ip)) return;
          setSelectedIp(ip);
          setModalOpen(true);
          setDetailLoading(true);
          setDetailError(null);
          setDetailData(null);
          try {
            const data = await ipService.fetchIpDetails(ip);
            setDetailData(data);
          } catch (err) {
            setDetailError(err instanceof Error ? err.message : '发生未知错误');
          } finally {
            setDetailLoading(false);
          }
        };

        return (
          <div className="app-shell min-h-screen font-sans text-slate-900 dark:text-slate-100 transition-colors duration-300">
            <div className="app-orb app-orb-1"></div>
            <div className="app-orb app-orb-2"></div>
            <header className="header-shell surface-card border-b border-slate-200/70 dark:border-white/10 sticky top-0 z-30 bg-opacity-85 dark:bg-opacity-85 backdrop-blur-xl">
              <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="brand-badge p-1.5 rounded-xl text-white">
                      <ShieldCheck className="w-6 h-6" />
                  </div>
                  <h1 className="brand-title text-[1.02rem] font-semibold text-slate-900 dark:text-white">IP 哨兵</h1>
                </div>
                <div className="flex items-center gap-2">
                   <StylePresetToggle value={stylePreset} onChange={setStylePreset} />
                   <ThemeToggle />
                    <a href="https://github.com/jy02739244/ip-query-worker" target="_blank" rel="noreferrer" className="icon-button p-2.5 text-slate-500 hover:text-slate-900 dark:text-slate-300 dark:hover:text-white transition">
                       <Github className="w-5 h-5" />
                    </a>
                 </div>
              </div>
            </header>

            <main className="relative z-10 py-6">
              <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <ConnectivitySection className="mb-5" style={{ marginTop: 0 }} />

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                  {rows.map((row) => (
                    <StatusCard
                      key={row.id}
                      data={row}
                      stylePreset={stylePreset}
                      onViewDetails={handleViewDetails}
                      onRetry={() => {
                          const fetchFn = FETCH_MAP[row.id];
                          if (!fetchFn) return; // 'current' 无需重试
                          updateRow(row.id, { isLoading: true, error: undefined });
                          fetchFn().then(d => updateRow(row.id, d));
                      }}
                    />
                  ))}
                </div>

                {/* --- 泄漏检测区域 --- */}
                <div className="surface-strong rounded-3xl p-5 md:p-6 mt-8">
                  <LeakDetectionSection stylePreset={stylePreset} />
                </div>

                <div className="footer-shell surface-strong mt-12 px-5 py-5 flex flex-col md:flex-row items-center justify-between text-sm text-slate-500 dark:text-slate-400 gap-4 rounded-3xl">
                    <div className="flex items-center gap-2">
                        <Globe className="w-4 h-4" />
                        <span>基于 Cloudflare & React 构建</span>
                    </div>
                    <div>数据源包括 ipwho.is, ipapi.is, ip-api.com 等。</div>
                </div>
              </div>
            </main>

            <IpDetailModal
              isOpen={modalOpen}
              onClose={handleCloseModal}
              onRetry={() => handleViewDetails(selectedIp)}
              selectedIp={selectedIp}
              data={detailData}
              loading={detailLoading}
              error={detailError}
            />
          </div>
        );
      };

      const root = createRoot(document.getElementById('root'));
      root.render(<App />);
    </script>
  </body>
</html>
`;
}
