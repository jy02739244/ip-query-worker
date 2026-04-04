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
      if (ip && !validateQueryTarget(ip)) {
        return new Response(JSON.stringify({ error: '无效的 IP 地址或域名格式' }), {
          status: 400,
          headers: {
            'content-type': 'application/json;charset=UTF-8',
            ...corsHeaders,
            ...SECURITY_HEADERS,
          },
        });
      }

      const apiUrl = `https://api.ipapi.is${ip ? `?q=${encodeURIComponent(ip)}` : ''}`;

      try {
        const response = await fetch(apiUrl, {
          headers: {
            'Accept': 'application/json',
          },
        });

        const data = await response.json().catch(() => null);

        if (!response.ok) {
          return new Response(JSON.stringify(data || { error: `上游服务返回错误: HTTP ${response.status}` }), {
            status: response.status,
            headers: {
              'content-type': 'application/json;charset=UTF-8',
              ...corsHeaders,
              ...SECURITY_HEADERS,
            },
          });
        }

        return new Response(JSON.stringify(data), {
          status: response.status,
          headers: {
            'content-type': 'application/json;charset=UTF-8',
            'Cache-Control': 'public, max-age=60',
            ...corsHeaders,
            ...SECURITY_HEADERS,
          },
        });
      } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
          status: 500,
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
    <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>

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
        ipsb: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%232563eb' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Ccircle cx='12' cy='12' r='10'/%3E%3Cpath d='M2 12h20'/%3E%3Cpath d='M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z'/%3E%3C/svg%3E",
        chatgpt: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%2310a37f'%3E%3Cpath d='M22.2819 9.8211a5.9847 5.9847 0 0 0-.5157-4.9108 6.0462 6.0462 0 0 0-6.5098-2.9A6.0651 6.0651 0 0 0 4.9807 4.1818a5.9847 5.9847 0 0 0-3.9977 2.9 6.0462 6.0462 0 0 0 .7427 7.0966 5.98 5.98 0 0 0 .511 4.9107 6.0462 6.0462 0 0 0 6.5146 2.9001A5.9847 5.9847 0 0 0 13.2599 24a6.0557 6.0557 0 0 0 5.7718-4.2058 5.9894 5.9894 0 0 0 3.9977-2.9001 6.0557 6.0557 0 0 0-.7475-7.0729zm-9.022 12.6081a4.4755 4.4755 0 0 1-2.8764-1.0408l.1419-.0804 4.7783-2.7582a.7948.7948 0 0 0 .3927-.6813v-6.7369l2.02 1.1686a.071.071 0 0 1 .038.052v5.5826a4.504 4.504 0 0 1-4.4945 4.4944zm-9.6607-4.1254a4.4708 4.4708 0 0 1-.5346-3.0137l.142.0852 4.783 2.7582a.7712.7712 0 0 0 .7806 0l5.8428-3.3685v2.3324a.0804.0804 0 0 1-.0332.0615L9.74 19.9502a4.4992 4.4992 0 0 1-6.1408-1.6464zM2.3408 7.8956a4.485 4.485 0 0 1 2.3655-1.9728V11.6a.7664.7664 0 0 0 .3879.6765l5.8144 3.3543-2.0201 1.1685a.0757.0757 0 0 1-.071 0l-4.8303-2.7865A4.504 4.504 0 0 1 2.3408 7.872zm16.5963 3.8558L13.1038 8.3829a.071.071 0 0 1-.038-.052V2.7482a4.4992 4.4992 0 0 1 4.4945 4.4944v5.8403a.7853.7853 0 0 0-.3832-.6813l-.2399-.6498zM6.803 3.3029l2.0201-1.1685a.0757.0757 0 0 1 .071 0l4.8303 2.7865a4.504 4.504 0 0 1 2.1461 3.8257l-.1466-.0852-4.783-2.7629a.7759.7759 0 0 0-.7854 0L4.3126 9.267V6.9346a.0804.0804 0 0 1 .0332-.0615l4.9522-3.2902a4.485 4.485 0 0 1-2.495 3.72zm8.1174 9.3485a4.4992 4.4992 0 0 1-6.1408 1.6511l-.1466-.0852 4.783-2.7582a.7759.7759 0 0 0 .3927-.6813v-6.7369l2.0201-1.1685a.0757.0757 0 0 1 .071 0l4.8303 2.7865a4.504 4.504 0 0 1-2.1461 3.8257zM11.9996 11.9996a1.1685 1.1685 0 1 1 1.1685-1.1685 1.1685 1.1685 0 0 1-1.1685 1.1685z'/%3E%3C/svg%3E",
        xcom: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='black'%3E%3Cpath d='M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z'/%3E%3C/svg%3E",
        openai: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='black'%3E%3Cpath d='M22.2819 9.8211a5.9847 5.9847 0 0 0-.5157-4.9108 6.0462 6.0462 0 0 0-6.5098-2.9A6.0651 6.0651 0 0 0 4.9807 4.1818a5.9847 5.9847 0 0 0-3.9977 2.9 6.0462 6.0462 0 0 0 .7427 7.0966 5.98 5.98 0 0 0 .511 4.9107 6.0462 6.0462 0 0 0 6.5146 2.9001A5.9847 5.9847 0 0 0 13.2599 24a6.0557 6.0557 0 0 0 5.7718-4.2058 5.9894 5.9894 0 0 0 3.9977-2.9001 6.0557 6.0557 0 0 0-.7475-7.0729zm-9.022 12.6081a4.4755 4.4755 0 0 1-2.8764-1.0408l.1419-.0804 4.7783-2.7582a.7948.7948 0 0 0 .3927-.6813v-6.7369l2.02 1.1686a.071.071 0 0 1 .038.052v5.5826a4.504 4.504 0 0 1-4.4945 4.4944zm-9.6607-4.1254a4.4708 4.4708 0 0 1-.5346-3.0137l.142.0852 4.783 2.7582a.7712.7712 0 0 0 .7806 0l5.8428-3.3685v2.3324a.0804.0804 0 0 1-.0332.0615L9.74 19.9502a4.4992 4.4992 0 0 1-6.1408-1.6464zM2.3408 7.8956a4.485 4.485 0 0 1 2.3655-1.9728V11.6a.7664.7664 0 0 0 .3879.6765l5.8144 3.3543-2.0201 1.1685a.0757.0757 0 0 1-.071 0l-4.8303-2.7865A4.504 4.504 0 0 1 2.3408 7.872zm16.5963 3.8558L13.1038 8.3829v5.5826a4.504 4.504 0 0 1-4.4945 4.4944zM11.9996 11.9996a1.1685 1.1685 0 1 1 1.1685-1.1685 1.1685 1.1685 0 0 1-1.1685 1.1685z'/%3E%3C/svg%3E",
        grok: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 512 509.641' fill-rule='evenodd' clip-rule='evenodd'%3E%3Cpath d='M115.612 0h280.776C459.975 0 512 52.026 512 115.612v278.416c0 63.587-52.025 115.613-115.612 115.613H115.612C52.026 509.641 0 457.615 0 394.028V115.612C0 52.026 52.026 0 115.612 0z'/%3E%3Cpath fill='%23fff' d='M213.235 306.019l178.976-180.002v.169l51.695-51.763c-.924 1.32-1.86 2.605-2.785 3.89-39.281 54.164-58.46 80.649-43.07 146.922l-.09-.101c10.61 45.11-.744 95.137-37.398 131.836-46.216 46.306-120.167 56.611-181.063 14.928l42.462-19.675c38.863 15.278 81.392 8.57 111.947-22.03 30.566-30.6 37.432-75.159 22.065-112.252-2.92-7.025-11.67-8.795-17.792-4.263l-124.947 92.341zm-25.786 22.437l-.033.034L68.094 435.217c7.565-10.429 16.957-20.294 26.327-30.149 26.428-27.803 52.653-55.359 36.654-94.302-21.422-52.112-8.952-113.177 30.724-152.898 41.243-41.254 101.98-51.661 152.706-30.758 11.23 4.172 21.016 10.114 28.638 15.639l-42.359 19.584c-39.44-16.563-84.629-5.299-112.207 22.313-37.298 37.308-44.84 102.003-1.128 143.81z'/%3E%3C/svg%3E",
        ipapi: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%237c3aed' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Crect x='2' y='2' width='20' height='20' rx='5' ry='5'/%3E%3Cpath d='M12 12m-3 0a3 3 0 1 0 6 0a3 3 0 1 0 -6 0'/%3E%3C/svg%3E"
      };

      // --- 枚举与工具函数 ---
      const RiskLevel = {
        VERY_LOW: '极度纯净',
        LOW: '纯净',
        ELEVATED: '轻微风险',
        HIGH: '高风险',
        CRITICAL: '极度危险',
        UNKNOWN: '未知'
      };

      function getFlagEmoji(countryCode) {
        if (!/^[A-Z]{2}$/i.test(String(countryCode || ''))) return '🏳️';
        const codePoints = countryCode
          .toUpperCase()
          .split('')
          .map((c) => 127397 + c.charCodeAt(0));
        return String.fromCodePoint(...codePoints);
      }

      function calculateAbuseScore(data) {
        const companyScoreStr = data.company?.abuser_score;
        const asnScoreStr = data.asn?.abuser_score;

        let company = 0;
        let asn = 0;

        if (companyScoreStr && companyScoreStr !== 'Unknown') company = parseFloat(companyScoreStr) || 0;
        if (asnScoreStr && asnScoreStr !== 'Unknown') asn = parseFloat(asnScoreStr) || 0;

        // 基础分公式: (运营商分 + ASN分) / 2 * 5
        let baseScore = ((company + asn) / 2) * 5;

        const riskFlags = [
          data.is_crawler, data.is_proxy, data.is_vpn,
          data.is_tor, data.is_abuser, data.is_bogon
        ];

        // 每个风险项增加 15%
        const riskCount = riskFlags.filter(flag => flag === true).length;
        const riskAddition = riskCount * 0.15;

        const finalScore = baseScore + riskAddition;

        if (baseScore === 0 && riskAddition === 0) {
          return { score: null, level: RiskLevel.UNKNOWN, percentage: null };
        }

        const percentage = finalScore * 100;
        let level = RiskLevel.VERY_LOW;

        // 按照你要求的阈值判断等级
        if (percentage >= 100) level = RiskLevel.CRITICAL;
        else if (percentage >= 20) level = RiskLevel.HIGH;
        else if (percentage >= 5) level = RiskLevel.ELEVATED;
        else if (percentage >= 0.25) level = RiskLevel.LOW;

        return { score: finalScore, level, percentage };
      }

      function getRiskBadgeColor(level) {
        switch (level) {
          case RiskLevel.CRITICAL: return 'bg-red-100 text-red-800 border-red-200 dark:bg-red-950/35 dark:text-red-300 dark:border-red-900/50';
          case RiskLevel.HIGH: return 'bg-orange-100 text-orange-800 border-orange-200 dark:bg-orange-950/35 dark:text-orange-300 dark:border-orange-900/50';
          case RiskLevel.ELEVATED: return 'bg-yellow-100 text-yellow-800 border-yellow-200 dark:bg-yellow-950/35 dark:text-yellow-300 dark:border-yellow-900/50';
          case RiskLevel.LOW: return 'bg-emerald-100 text-emerald-800 border-emerald-200 dark:bg-emerald-950/35 dark:text-emerald-300 dark:border-emerald-900/50';
          case RiskLevel.VERY_LOW: return 'bg-green-100 text-green-800 border-green-200 dark:bg-green-950/35 dark:text-green-300 dark:border-green-900/50';
          default: return 'bg-gray-100 text-gray-800 border-gray-200 dark:bg-slate-800/90 dark:text-slate-300 dark:border-slate-700';
        }
      }

      function getThreatColor(scoreStr) {
          if (!scoreStr) return 'bg-blue-50 text-blue-700 dark:bg-blue-950/35 dark:text-blue-300';
          const score = parseFloat(scoreStr);
          if (isNaN(score)) return 'bg-gray-100 text-gray-600 dark:bg-slate-800/90 dark:text-slate-300';
          if (score < 0.001) return 'bg-green-100 text-green-700 dark:bg-green-950/35 dark:text-green-300';
          if (score < 0.01) return 'bg-blue-100 text-blue-700 dark:bg-blue-950/35 dark:text-blue-300';
          if (score < 0.1) return 'bg-yellow-100 text-yellow-700 dark:bg-yellow-950/35 dark:text-yellow-300';
          return 'bg-red-100 text-red-700 dark:bg-red-950/35 dark:text-red-300';
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
        <div className="flex items-center gap-2 mb-3 text-slate-800 dark:text-slate-200 pb-2 border-b border-slate-100 dark:border-slate-700">
            <Icon className="w-5 h-5 text-indigo-500 dark:text-indigo-300" />
            <h3 className="font-bold text-base">{title}</h3>
        </div>
      );

      const InfoItem = ({ label, value, highlight = false }) => (
        <div className="flex flex-col sm:flex-row justify-between py-2">
          <span className="text-slate-500 dark:text-slate-400 text-sm font-medium min-w-[120px]">{label}</span>
          <span className={\`text-sm sm:text-right mt-1 sm:mt-0 break-words \${highlight ? 'font-bold text-slate-900 dark:text-slate-100' : 'text-slate-700 dark:text-slate-300'}\`}>
            {value}
          </span>
        </div>
      );

      const DETAIL_PANEL_CLASS = 'rounded-xl border border-slate-200/90 bg-white/90 p-4 shadow-sm dark:border-white/10 dark:bg-slate-900/72';
      const DETAIL_PANEL_MUTED_CLASS = 'rounded-xl border border-slate-200/80 bg-slate-50/90 p-4 shadow-sm dark:border-white/10 dark:bg-slate-900/56';

      const BoolBadge = ({ value, trueLabel = '是', falseLabel = '否' }) => {
        if (value) {
          return <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-red-50 text-red-700 border border-red-100 dark:bg-red-950/30 dark:text-red-300 dark:border-red-900/50"><AlertTriangle className="w-3 h-3" /> {trueLabel}</span>;
        }
        return <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-green-50 text-green-700 border border-green-100 dark:bg-green-950/30 dark:text-green-300 dark:border-green-900/50"><CheckCircle2 className="w-3 h-3" /> {falseLabel}</span>;
      };

      // 安全检测项配置（数据驱动渲染，消除重复 JSX）
      const SECURITY_CHECK_ITEMS = [
        { key: 'is_mobile', label: '移动流量' },
        { key: 'is_datacenter', label: '数据中心' },
        { key: 'is_satellite', label: '卫星网络' },
        { key: 'is_crawler', label: '爬虫' },
        { key: 'is_proxy', label: '代理服务器' },
        { key: 'is_vpn', label: 'VPN' },
        { key: 'is_tor', label: 'Tor 网络' },
        { key: 'is_abuser', label: '滥用 IP' },
        { key: 'is_bogon', label: '虚假 IP' },
      ];

      const IpDetailModal = ({ isOpen, onClose, data, loading, error }) => {
        // ESC 键关闭 Modal
        useEffect(() => {
          if (!isOpen) return;
          const handleKeyDown = (e) => {
            if (e.key === 'Escape') onClose();
          };
          document.addEventListener('keydown', handleKeyDown);
          return () => document.removeEventListener('keydown', handleKeyDown);
        }, [isOpen, onClose]);

        if (!isOpen) return null;

        const handleBackdropClick = (e) => {
          if (e.target === e.currentTarget) onClose();
        };

        let content;
        let riskInfo = { score: null, level: RiskLevel.UNKNOWN, percentage: null };
        if (data) riskInfo = calculateAbuseScore(data);

        if (loading) {
          content = (
            <div className="flex flex-col items-center justify-center py-20">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600 mb-4"></div>
              <p className="text-slate-500 dark:text-slate-400 font-medium">正在深入分析 IP 情报...</p>
            </div>
          );
        } else if (error) {
          content = (
            <div className="flex flex-col items-center justify-center py-20 text-center">
              <div className="bg-red-50 dark:bg-red-950/30 p-4 rounded-full mb-4">
                  <AlertTriangle className="w-8 h-8 text-red-500" />
              </div>
              <h3 className="text-lg font-bold text-slate-800 dark:text-slate-200">获取详情失败</h3>
              <p className="text-slate-500 dark:text-slate-400 mt-2 max-w-xs">{error}</p>
              <button onClick={onClose} className="mt-6 px-4 py-2 bg-slate-100 hover:bg-slate-200 dark:bg-slate-700 dark:hover:bg-slate-600 text-slate-700 dark:text-slate-200 rounded-lg transition">关闭</button>
            </div>
          );
        } else if (data) {
          content = (
            <div className="space-y-6 animate-slide-up">
              {/* 标题区 */}
              <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-xl font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                        🔍 IP 详细信息
                    </h2>
                    <span className="text-xs text-slate-400 dark:text-slate-500 mt-1 block">数据来源: ipapi.is</span>
                  </div>
                  <button onClick={onClose} className="p-2 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-full transition">
                      <X className="w-5 h-5 text-slate-500 dark:text-slate-400" />
                  </button>
              </div>

              {/* 1. 基本信息 */}
              <div className={DETAIL_PANEL_CLASS}>
                  <SectionTitle icon={Info} title="基本信息" />
                  <div className="space-y-1">
                      <div className="flex flex-col sm:flex-row justify-between py-2 border-b border-slate-50 dark:border-slate-700">
                          <span className="text-slate-500 dark:text-slate-400 text-sm font-medium">IP 地址</span>
                          <span className="ip-addr text-lg font-mono font-bold text-slate-900 dark:text-slate-100 text-right">{data.ip}</span>
                      </div>
                      <InfoItem label="区域注册机构" value={data.rir || '未知'} highlight />
                      <InfoItem
                        label="运营商 / ASN 类型"
                        value={
                            <span>
                                <IpTypeBadge type={data.company?.type} /> / <IpTypeBadge type={data.asn?.type} />
                            </span>
                        }
                      />
                      <div className="flex flex-col sm:flex-row justify-between py-2 items-center">
                          <span className="text-slate-500 dark:text-slate-400 text-sm font-medium flex items-center gap-1">
                             综合滥用评分
                             <div className="group relative">
                                <span className="w-4 h-4 rounded-full bg-blue-100 text-blue-600 dark:bg-blue-950/40 dark:text-blue-300 text-[10px] flex items-center justify-center cursor-help font-bold">?</span>
                                <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 w-48 bg-slate-800 text-white text-xs p-2 rounded shadow-lg opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-10">
                                    算法: (运营商分+ASN分)/2 * 5 + 风险项加成
                                </div>
                             </div>
                          </span>
                          <div className="text-right mt-1 sm:mt-0">
                              {riskInfo.score !== null ? (
                                  <span className={\`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-sm font-bold border \${getRiskBadgeColor(riskInfo.level)}\`}>
                                      {riskInfo.percentage?.toFixed(2)}% {riskInfo.level}
                                  </span>
                              ) : <span className="text-slate-400">未知</span>}
                          </div>
                      </div>
                  </div>
              </div>

              {/* 2. 安全检测 */}
              <div className={DETAIL_PANEL_CLASS}>
                   <SectionTitle icon={ShieldCheck} title="安全检测" />
                   <div className="grid grid-cols-1 sm:grid-cols-2 gap-y-2 gap-x-8">
                        {SECURITY_CHECK_ITEMS.map(({ key, label }) => (
                            <div key={key} className="flex justify-between items-center py-1">
                                <span className="text-slate-600 dark:text-slate-300 text-sm">{label}</span>
                                <BoolBadge value={data[key]} trueLabel="是" falseLabel="否" />
                            </div>
                        ))}
                   </div>
              </div>

              {/* 3. 位置信息 */}
              <div className={DETAIL_PANEL_CLASS}>
                  <SectionTitle icon={MapPin} title="位置信息" />
                  <div className="space-y-1">
                      <InfoItem label="国家" value={\`\${data.location?.country || '未知'} (\${data.location?.country_code || '-'}) \${data.location?.is_eu_member ? '🇪🇺' : ''}\`} />
                      {data.location?.state && <InfoItem label="省份/州" value={data.location.state} />}
                      {data.location?.city && <InfoItem label="城市" value={data.location.city} />}
                      {data.location?.zip && <InfoItem label="邮编" value={data.location.zip} />}
                      <InfoItem label="坐标" value={\`\${data.location?.latitude || '-'}, \${data.location?.longitude || '-'}\`} />
                      <InfoItem label="时区" value={data.location?.timezone || '-'} />
                      <InfoItem label="当地时间" value={data.location?.local_time || '-'} />
                  </div>
              </div>

              {/* 4. 运营商信息 */}
              <div className={DETAIL_PANEL_CLASS}>
                   <SectionTitle icon={Server} title="运营商信息" />
                   <div className="space-y-1">
                       <InfoItem label="运营商名称" value={data.company?.name || '未知'} highlight />
                       <InfoItem label="域名" value={data.company?.domain || '-'} />
                       <InfoItem label="类型" value={<IpTypeBadge type={data.company?.type} />} />
                       <InfoItem label="网络范围" value={data.company?.network || '-'} />
                       <div className="flex flex-col sm:flex-row justify-between py-2">
                          <span className="text-slate-500 dark:text-slate-400 text-sm font-medium">滥用评分</span>
                          <span className="mt-1 sm:mt-0">
                            {data.company?.abuser_score ? (
                                <span className={\`px-2 py-0.5 rounded text-xs font-bold \${getThreatColor(data.company.abuser_score)}\`}>
                                    {data.company.abuser_score}
                                </span>
                            ) : '-'}
                          </span>
                       </div>
                   </div>
              </div>

              {/* 5. ASN 信息 */}
              <div className={DETAIL_PANEL_CLASS}>
                   <SectionTitle icon={Activity} title="ASN 信息" />
                   <div className="space-y-1">
                       <InfoItem label="ASN 编号" value={data.asn?.asn ? \`AS\${data.asn.asn}\` : '未知'} highlight />
                       <InfoItem label="组织" value={data.asn?.org || '-'} />
                       <InfoItem label="路由" value={data.asn?.route || '-'} />
                       <InfoItem label="类型" value={<IpTypeBadge type={data.asn?.type} />} />
                       <InfoItem label="国家代码" value={data.asn?.country || '-'} />
                       <div className="flex flex-col sm:flex-row justify-between py-2">
                          <span className="text-slate-500 dark:text-slate-400 text-sm font-medium">滥用评分</span>
                          <span className="mt-1 sm:mt-0">
                            {data.asn?.abuser_score ? (
                                <span className={\`px-2 py-0.5 rounded text-xs font-bold \${getThreatColor(data.asn.abuser_score)}\`}>
                                    {data.asn.abuser_score}
                                </span>
                            ) : '-'}
                          </span>
                       </div>
                   </div>
              </div>

              {/* 6. 滥用举报联系方式 */}
              {data.abuse && (
                  <div className={DETAIL_PANEL_MUTED_CLASS}>
                      <SectionTitle icon={Shield} title="滥用举报联系方式" />
                      <div className="space-y-1 text-sm">
                          {data.abuse.name && <InfoItem label="联系人" value={data.abuse.name} />}
                          {data.abuse.email && <InfoItem label="邮箱" value={data.abuse.email} />}
                          {data.abuse.phone && <InfoItem label="电话" value={data.abuse.phone} />}
                          {data.abuse.address && <InfoItem label="地址" value={data.abuse.address} />}
                      </div>
                  </div>
              )}
            </div>
          );
        }

        return (
          <div className="fixed inset-0 z-50 overflow-y-auto" role="dialog" aria-modal="true" aria-label="IP 详细信息">
            <div className="fixed inset-0 bg-slate-900/70 backdrop-blur-sm transition-opacity" onClick={handleBackdropClick}></div>
            <div className="flex min-h-full items-center justify-center p-4 text-center sm:p-0">
              <div className="relative transform overflow-hidden rounded-2xl border border-white/70 bg-white/95 dark:border-white/10 dark:bg-slate-950/92 text-left shadow-2xl backdrop-blur-xl transition-all sm:my-8 sm:w-full sm:max-w-3xl max-h-[90vh] overflow-y-auto scrollbar-hide">
                <div className="absolute top-4 right-4 z-10 md:hidden">
                  <button type="button" aria-label="关闭" className="rounded-full bg-white/80 dark:bg-slate-900/80 p-2 text-slate-400 dark:text-slate-500 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-white/10 transition focus:outline-none" onClick={onClose}>
                    <X className="w-5 h-5" />
                  </button>
                </div>
                <div className="p-6 sm:p-8 bg-[#f8fafc] dark:bg-[#07101d]">{content}</div>
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

      // --- 数据服务层 (客户端直接请求) ---
      const ipService = {
        fetchChatGPT: createTraceFetcher('https://chatgpt.com/cdn-cgi/trace'),
        fetchXcom: createTraceFetcher('https://help.x.com/cdn-cgi/trace'),
        fetchOpenAI: createTraceFetcher('https://openai.com/cdn-cgi/trace'),
        fetchGrok: createTraceFetcher('https://grok.com/cdn-cgi/trace'),
        // IPv4
        fetchIpSbV4: async () => {
          try {
            const res = await fetchWithTimeout('https://api-ipv4.ip.sb/geoip');
            if (!res.ok) throw new Error('Error');
            const data = await res.json();
            return buildSourceSuccessResult({ ip: data.ip, isp: data.isp, countryCode: data.country_code, countryName: data.country });
          } catch (e) { return createSourceErrorResult('加载失败'); }
        },
        // IPv6
        fetchIpSbV6: async () => {
          try {
            const res = await fetchWithTimeout('https://api-ipv6.ip.sb/geoip');
            if (!res.ok) throw new Error('Error');
            const data = await res.json();
            return buildSourceSuccessResult({ ip: data.ip, isp: data.isp, countryCode: data.country_code, countryName: data.country });
          } catch (e) { return createSourceErrorResult('加载失败'); }
        },
        // IPAPI.is 基础信息查询 (优先使用官方 API，失败后回退备用端点)
        fetchIpApi: async () => {
          const parseIpApiResponse = (data) => buildSourceSuccessResult({
            ip: data.ip,
            isp: data.asn?.org,
            countryCode: data.location?.country_code,
            countryName: data.location?.country,
          });
          try {
            const res = await fetchWithTimeout('https://api.ipapi.is/', {}, 5000);
            if (!res.ok) throw new Error('Error');
            const data = await res.json();
            return parseIpApiResponse(data);
          } catch (e) {
            try {
              const res = await fetchWithTimeout('https://api.ipapi.cmliussss.net/');
              if (!res.ok) throw new Error('Error');
              const data = await res.json();
              return parseIpApiResponse(data);
            } catch (e2) { return createSourceErrorResult('加载失败'); }
          }
        },
        // 详情查询 (使用 Worker 中转)
        fetchIpDetails: async (ip) => {
          if (!isQueryableTarget(ip)) throw new Error('详情查询目标无效');
          const res = await fetchWithTimeout(\`/api/ipapi?q=\${encodeURIComponent(ip)}\`);
          if (!res.ok) throw new Error('详情查询失败');
          return await res.json();
        },
        fetchWebRTCRegion: async (ip) => {
          const res = await fetchWithTimeout(\`https://api.ip.sb/geoip/\${encodeURIComponent(ip)}\`);
          if (!res.ok) throw new Error('区域查询失败');
          return await res.json();
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
        ipv4: () => ipService.fetchIpSbV4(),
        ipv6: () => ipService.fetchIpSbV6(),
        ipapi: () => ipService.fetchIpApi(),
        chatgpt: () => ipService.fetchChatGPT(),
        xcom: () => ipService.fetchXcom(),
        openai: () => ipService.fetchOpenAI(),
        grok: () => ipService.fetchGrok(),
      };

      // 数据源卡片配置（配置驱动，消除重复模板代码）
      const SOURCE_CONFIGS = [
        { id: 'ipv4', sourceName: 'IP.SB IPv4', sourceUrl: 'https://ip.sb', sourceIcon: ICONS.ipsb, isp: '...' },
        { id: 'ipv6', sourceName: 'IP.SB IPv6', sourceUrl: 'https://ip.sb', sourceIcon: ICONS.ipsb, isp: '...' },
        { id: 'ipapi', sourceName: 'IPAPI.is', sourceUrl: 'https://ipapi.is', sourceIcon: ICONS.ipapi, isp: '...' },
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

        const readyCount = rows.filter((row) => isSuccessfulRowResult(row)).length;
        const errorCount = rows.filter((row) => !row.isLoading && !!row.error).length;
        const countryCount = new Set(rows.filter((row) => isSuccessfulRowResult(row)).map((row) => normalizeCountryCode(row.countryCode)).filter(Boolean)).size;

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
                <div className="hero-panel mb-5 text-center md:text-left surface-strong rounded-3xl p-5 md:p-6">
                <div className="flex flex-col md:flex-row md:items-end md:justify-between gap-5">
                  <div>
                    <h2 className="hero-title text-[1.45rem] md:text-[2.05rem] font-semibold mb-2 title-gradient">网络身份分析</h2>
                    <p className="text-slate-600/90 dark:text-slate-300/90 max-w-xl leading-relaxed md:text-[15px]">
                      分析各服务商下的连接可见性,检测 IP 暴露情况。
                    </p>
                  </div>
                  <div className="flex flex-wrap justify-center md:justify-end gap-2">
                    <span className="hero-chip">已就绪: {readyCount}</span>
                    <span className="hero-chip">异常: {errorCount}</span>
                    <span className="hero-chip">地区数: {countryCount}</span>
                  </div>
                </div>
                </div>

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
                    <div>数据源包括 ipapi.is, ip.sb 等。</div>
                </div>
              </div>
            </main>

            <IpDetailModal
              isOpen={modalOpen}
              onClose={() => setModalOpen(false)}
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
