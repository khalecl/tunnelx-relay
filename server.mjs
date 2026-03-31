import http from 'http';
import net from 'net';
import { gotScraping } from 'got-scraping';

const PORT = process.env.PORT || 3000;

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Max-Age': '86400',
};

function json(res, data, status = 200) {
  res.writeHead(status, { ...CORS, 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

// ── TCP test ──
function tcpTest(host, port, timeout = 7000) {
  return new Promise(resolve => {
    const t0 = Date.now();
    const sock = new net.Socket();
    sock.setTimeout(timeout);
    sock.on('connect', () => { sock.destroy(); resolve({ status: 'alive', latency: Date.now() - t0 }); });
    sock.on('timeout', () => { sock.destroy(); resolve({ status: 'dead', latency: Date.now() - t0, error: 'timeout' }); });
    sock.on('error', e => { sock.destroy(); resolve({ status: e.code === 'ECONNREFUSED' ? 'alive' : 'dead', latency: Date.now() - t0, error: e.message }); });
    sock.connect(parseInt(port), host);
  });
}

// ── SOCKS handshake test ──
function socksTest(host, port, version = 5, timeout = 8000) {
  return new Promise(resolve => {
    const t0 = Date.now();
    const sock = new net.Socket();
    sock.setTimeout(timeout);
    sock.on('connect', () => {
      if (version === 5) sock.write(Buffer.from([0x05, 0x01, 0x00]));
      else { const b = Buffer.alloc(9); b[0]=4;b[1]=1;b.writeUInt16BE(80,2);b[7]=1;b[8]=0; sock.write(b); }
    });
    sock.on('data', d => {
      sock.destroy();
      const ms = Date.now() - t0;
      if (version === 5 && d.length >= 2 && d[0] === 0x05) resolve({ status: 'alive', latency: ms, detail: `SOCKS5 (auth:${d[1]})` });
      else if (version === 4 && d.length >= 2 && d[0] === 0x00) resolve({ status: 'alive', latency: ms, detail: 'SOCKS4 OK' });
      else resolve({ status: 'alive', latency: ms, detail: 'Port open (non-SOCKS)' });
    });
    sock.on('timeout', () => { sock.destroy(); resolve({ status: 'dead', latency: Date.now() - t0, error: 'timeout' }); });
    sock.on('error', e => { sock.destroy(); resolve({ status: 'dead', latency: Date.now() - t0, error: e.message }); });
    sock.connect(parseInt(port), host);
  });
}

// ── Fetch via got-scraping ──
async function fetchThrough(targetUrl, proxyUrl, timeout = 20000) {
  const t0 = Date.now();
  const opts = {
    url: targetUrl,
    headerGeneratorOptions: { browsers: ['chrome'], operatingSystems: ['windows'], locales: ['ru-RU,ru;q=0.9','en-US,en;q=0.8'] },
    https: { ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256' },
    http2: true, decompress: true, followRedirect: true, maxRedirects: 5,
    timeout: { request: timeout }, retry: { limit: 0 }, responseType: 'text',
  };
  if (proxyUrl) opts.proxyUrl = proxyUrl;

  console.log(`  🌐 got-scraping → ${targetUrl}${proxyUrl ? ' via ' + proxyUrl : ''}`);
  const r = await gotScraping(opts);
  const body = typeof r.body === 'string' ? r.body : r.body.toString('utf-8');
  console.log(`  ✓ HTTP ${r.statusCode} (${Date.now()-t0}ms, ${Math.round(body.length/1024)}KB)`);

  return { status: r.statusCode, headers: r.headers, body, latency: Date.now() - t0, httpVersion: r.httpVersion };
}

// ── Server ──
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  if (req.method === 'OPTIONS') { res.writeHead(204, CORS); res.end(); return; }

  // /health
  if (url.pathname === '/health') {
    return json(res, { status: 'ok', type: 'render-gotscraping', features: ['socks4','socks5','http','h2','tls-fp'], time: new Date().toISOString() });
  }

  // /test — test proxy via got-scraping (fetches test URL through proxy)
  if (url.pathname === '/test') {
    const host = url.searchParams.get('host');
    const port = url.searchParams.get('port') || '80';
    const proto = (url.searchParams.get('proto') || 'http').toLowerCase();
    if (!host) return json(res, { error: 'Missing host' }, 400);

    const proxyAddr = `${proto}://${host}:${port}`;
    console.log(`🔍 Test: ${proxyAddr}`);
    const t0 = Date.now();

    // Strategy 1: got-scraping through proxy (best — verifies full chain)
    const targets = ['http://httpbin.org/ip', 'http://ip-api.com/json', 'http://ifconfig.me/ip'];
    for (const target of targets) {
      try {
        console.log(`  → ${target} via ${proxyAddr}`);
        const r = await gotScraping({
          url: target, proxyUrl: proxyAddr,
          timeout: { request: 12000 }, retry: { limit: 0 },
          http2: false, followRedirect: true, responseType: 'text',
        });
        let exitIp = '';
        try {
          const b = r.body;
          if (b.includes('"origin"')) exitIp = JSON.parse(b).origin;
          else if (b.includes('"query"')) exitIp = JSON.parse(b).query;
          else exitIp = b.trim().split('\n')[0].substring(0, 45);
        } catch {}
        console.log(`  ✓ ALIVE (${Date.now()-t0}ms) exit: ${exitIp||'?'}`);
        return json(res, { host, port: +port, proto, status: 'alive', latency: Date.now()-t0, detail: `HTTP ${r.statusCode} from ${target}`, exitIp: exitIp||null });
      } catch (e) {
        console.log(`  ⚠ ${target}: ${e.message}`);
      }
    }

    // Strategy 2: Raw TCP (fallback — just checks if port is open)
    console.log(`  → Fallback: raw TCP to ${host}:${port}`);
    let result;
    if (proto === 'socks5' || proto === 'socks') result = await socksTest(host, port, 5);
    else if (proto === 'socks4') result = await socksTest(host, port, 4);
    else result = await tcpTest(host, port);

    console.log(`  → TCP: ${result.status} (${result.latency}ms)${result.detail ? ' ' + result.detail : ''}`);
    return json(res, { host, port: +port, proto, ...result });
  }

  // /fetch
  if (url.pathname === '/fetch') {
    const targetUrl = url.searchParams.get('url');
    const proxyUrl = url.searchParams.get('proxy') || null;
    if (!targetUrl) return json(res, { error: 'Missing url' }, 400);

    console.log(`🌐 Fetch: ${targetUrl}${proxyUrl ? ' via ' + proxyUrl : ' (direct)'}`);
    try {
      const result = await fetchThrough(targetUrl, proxyUrl);
      const ct = (result.headers || {})['content-type'] || 'text/html';
      res.writeHead(result.status || 200, { ...CORS, 'Content-Type': ct, 'X-Latency': String(result.latency), 'X-Proxy': proxyUrl || 'direct' });
      res.end(result.body);
    } catch (e) {
      console.log(`  ✗ ${e.message}`);
      json(res, { error: e.message, url: targetUrl, proxy: proxyUrl }, 502);
    }
    return;
  }

  // Default
  res.writeHead(200, { ...CORS, 'Content-Type': 'text/html' });
  res.end(`<html><body style="font-family:system-ui;background:#0b0f1a;color:#e8ecf4;display:flex;align-items:center;justify-content:center;height:100vh;margin:0"><div style="text-align:center"><h1 style="color:#60a5fa">⚡ TunnelX Relay</h1><p style="color:#94a3b8">got-scraping + SOCKS4/5 + HTTP/2</p><p style="color:#22c55e">/health · /test · /fetch</p></div></body></html>`);
});

server.listen(PORT, () => {
  console.log(`\n  ⚡ TunnelX Relay on port ${PORT}\n  SOCKS4/5 ✓  HTTP/2 ✓  TLS-FP ✓\n`);
});
