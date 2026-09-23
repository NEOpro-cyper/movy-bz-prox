// Bypass SSL verification globally (mimics PHP's CURLOPT_SSL_VERIFYPEER => false)
// Requires Node 18.13+ for fetch to reliably respect this
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const http = require('http');
const { Readable } = require('stream');
const { pipeline } = require('stream/promises');

const PORT = process.env.PORT || 3000;
const UPSTREAM_TIMEOUT = Number(process.env.UPSTREAM_TIMEOUT || 60000);

// Built once at startup — zero per-request cost
const SPOOFED_HEADERS = {
  'Referer': 'https://movy.sx/',
  'Origin': 'https://movy.sx',
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36',
  'Accept': '*/*',
  'Accept-Language': 'en-US,en;q=0.9',
  'sec-fetch-dest': 'empty',
  'sec-fetch-mode': 'cors',
  'sec-fetch-site': 'cross-site',
  'sec-ch-ua': '"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"',
  'sec-ch-ua-mobile': '?0',
  'sec-ch-ua-platform': '"Windows"',
};

// Applied to EVERY response (including errors) so the browser never
// masks a real 4xx/5xx as a "CORS error"
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': '*',
  'Access-Control-Expose-Headers': 'Content-Length, Content-Range, Accept-Ranges, ETag, Last-Modified',
};

// Whitelist of upstream headers to pass through. Deliberately EXCLUDES
// Access-Control-* (duplicate CORS headers = console errors) and
// Content-Encoding (undici already decompressed the body).
const PASS_THROUGH = [
  'content-type', 'content-length', 'content-range', 'accept-ranges',
  'etag', 'last-modified', 'cache-control', 'expires', 'content-disposition',
];

// Resolves any playlist reference (absolute, //host, /root, ../relative)
// against the final post-redirect URL and prefixes it with the proxy
function rewritePlaylist(text, baseUrl, proxyBase) {
  const absolutize = (u) => {
    try { return proxyBase + new URL(u, baseUrl).href } catch { return u }
  };
  return text.split('\n').map(line => {
    const t = line.trim();
    if (!t) return line;
    if (t.startsWith('#')) {
      return line.replace(/URI="([^"]+)"/g, (_, uri) => `URI="${absolutize(uri)}"`);
    }
    return absolutize(t);
  }).join('\n');
}

const server = http.createServer(async (req, res) => {
  // 1. CORS — set before anything else so every response carries them
  for (const [k, v] of Object.entries(CORS_HEADERS)) res.setHeader(k, v);

  if (req.method === 'OPTIONS') {
    // Browser caches the preflight for 24h instead of preflighting
    // before every single request (big speed win)
    res.writeHead(204, { 'Access-Control-Max-Age': '86400' });
    return res.end();
  }

  // Kill the upstream request the moment the player disconnects
  // (seek/pause/close) — frees sockets and bandwidth immediately
  const controller = new AbortController();
  res.on('close', () => { if (!res.writableEnded) controller.abort(); });

  // 2. Extract target URL from the raw request
  let requestUri = req.url;
  try {
    if (requestUri.includes('%')) requestUri = decodeURIComponent(requestUri);
  } catch {}

  const posHttp = requestUri.indexOf('http://');
  const posHttps = requestUri.indexOf('https://');
  if (posHttp === -1 && posHttps === -1) {
    res.writeHead(400, { 'Content-Type': 'text/plain' });
    return res.end(
      `Invalid proxy usage. Format: https://your-domain.com/?t=https://target.com/path\n\n` +
      `Debug Info:\nreq.url: ${req.url}\nDecoded: ${requestUri}`
    );
  }
  const startPos = (posHttp !== -1 && (posHttps === -1 || posHttp < posHttps)) ? posHttp : posHttps;
  const targetUrlStr = requestUri.substring(startPos);

  const isRead = req.method === 'GET' || req.method === 'HEAD';

  const fetchOptions = {
    method: req.method,
    headers: SPOOFED_HEADERS,
    redirect: 'follow',
    signal: controller.signal,
  };

  // 3. Stream request bodies straight through — nothing buffered in memory
  if (!isRead) {
    fetchOptions.body = Readable.toWeb(req);
    fetchOptions.duplex = 'half'; // required by undici for stream bodies
  }

  // Hard deadline so a stalled upstream can't hang the connection forever
  const timer = setTimeout(() => controller.abort(new Error('Upstream timeout')), UPSTREAM_TIMEOUT);

  try {
    const response = await fetch(targetUrlStr, fetchOptions);
    const finalUrl = response.url; // post-redirect URL — required for correct relative-URL rewriting
    const contentType = response.headers.get('content-type') || '';

    // WAF trap check
    if (finalUrl.includes('dontscrape')) {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      return res.end(
        `WAF Block Detected!\nThe target server trapped this request in the dontscrape loop.\n` +
        `Final URL: ${finalUrl}\nThis means the server is actively blocking your VPS IP or the spoofed headers.`
      );
    }

    // Build response headers from the whitelist (never forwards upstream CORS headers)
    const contentEncoding = response.headers.get('content-encoding');
    const outHeaders = {};
    for (const h of PASS_THROUGH) {
      if (h === 'content-length' && contentEncoding) continue; // body was decompressed; length invalid
      const v = response.headers.get(h);
      if (v !== null) outHeaders[h] = v;
    }
    if (!outHeaders['content-type']) outHeaders['content-type'] = 'application/octet-stream';
    // Let the browser cache responses; playlists stay fresh, segments cache 1h
    if (!outHeaders['cache-control'] && response.status < 400) {
      outHeaders['cache-control'] = (contentType.includes('mpegurl') || targetUrlStr.endsWith('.m3u8'))
        ? 'public, max-age=5'
        : 'public, max-age=3600';
    }

    // Bodyless responses: 204/304, HEAD, or no body
    if (req.method === 'HEAD' || response.status === 204 || response.status === 304 || !response.body) {
      res.writeHead(response.status, outHeaders);
      return res.end();
    }

    // Text-like responses may hide an m3u8 — sniff them
    const isPotentialM3u8 =
      targetUrlStr.endsWith('.m3u8') ||
      finalUrl.endsWith('.m3u8') ||
      ['.jpg', '.png', '.jpeg', '.gif'].some(ext => targetUrlStr.endsWith(ext)) ||
      contentType.includes('mpegurl') ||
      contentType.includes('text/');

    if (isPotentialM3u8) {
      const buffer = Buffer.from(await response.arrayBuffer());
      let bodyText = buffer.toString('utf-8');
      let isBase64 = false;
      let isM3u8 = false;

      // Guard the base64 sniff to small bodies — don't regex multi-MB HTML
      if (bodyText.length < 3_000_000 && /^[a-zA-Z0-9+/=\s]+$/.test(bodyText.trim())) {
        try {
          const decoded = Buffer.from(bodyText, 'base64').toString('utf-8');
          if (decoded.trim().startsWith('#EXTM3U')) {
            isBase64 = true;
            isM3u8 = true;
            bodyText = decoded;
          }
        } catch {}
      }
      if (!isM3u8 && bodyText.trim().startsWith('#EXTM3U')) isM3u8 = true;

      if (isM3u8) {
        const proxyBase = `${(req.headers['x-forwarded-proto'] || 'http').split(',')[0].trim()}://${req.headers.host}/?t=`;
        let rewritten = rewritePlaylist(bodyText, finalUrl, proxyBase);

        delete outHeaders['content-length']; // length changed after rewrite
        if (isBase64) {
          rewritten = Buffer.from(rewritten).toString('base64');
          outHeaders['content-type'] = contentType || 'application/octet-stream';
        } else {
          outHeaders['content-type'] = 'application/vnd.apple.mpegurl';
        }

        res.writeHead(response.status, outHeaders);
        return res.end(rewritten);
      }

      // Real image/file — send as-is
      res.writeHead(response.status, outHeaders);
      return res.end(buffer);
    }

    // Everything else (video segments, keys, audio): stream WITH backpressure.
    // pipeline() pauses the upstream read when res.write() returns false,
    // keeping memory flat no matter how slow the client is.
    res.writeHead(response.status, outHeaders);
    await pipeline(Readable.fromWeb(response.body), res);

  } catch (error) {
    // Client disconnects mid-stream land here too — nothing left to send them
    if (res.headersSent || res.destroyed) return res.destroy();
    console.error('[PROXY] Fetch Error:', error.message);
    res.writeHead(500, { 'Content-Type': 'text/plain' }); // CORS headers already applied
    return res.end('Error: ' + error.message);
  } finally {
    clearTimeout(timer);
  }
});

// Prevents "socket hang up" from Cloudflare/nginx (they idle ~60s)
server.keepAliveTimeout = 65000;
server.headersTimeout = 66000;

server.listen(PORT, () => {
  console.log(`Pure Node.js proxy server running on port ${PORT}`);
});
