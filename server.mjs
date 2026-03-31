import http from 'http';
import net from 'net';
import tls from 'tls';
import dns from 'dns';
import { Resolver } from 'dns/promises';
import { gotScraping } from 'got-scraping';
import { SocksProxyAgent } from 'socks-proxy-agent';

const PORT = process.env.PORT || 3000;

// ━━━ RUSSIAN TRUSTED CA CERTIFICATES ━━━━━━━━━━
const RUSSIAN_ROOT_CA = `-----BEGIN CERTIFICATE-----
MIIFwjCCA6qgAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwcDELMAkGA1UEBhMCUlUx
PzA9BgNVBAoMNlRoZSBNaW5pc3RyeSBvZiBEaWdpdGFsIERldmVsb3BtZW50IGFu
ZCBDb21tdW5pY2F0aW9uczEgMB4GA1UEAwwXUnVzc2lhbiBUcnVzdGVkIFJvb3Qg
Q0EwHhcNMjIwMzAxMjEwNDE1WhcNMzIwMjI3MjEwNDE1WjBwMQswCQYDVQQGEwJS
VTE/MD0GA1UECgw2VGhlIE1pbmlzdHJ5IG9mIERpZ2l0YWwgRGV2ZWxvcG1lbnQg
YW5kIENvbW11bmljYXRpb25zMSAwHgYDVQQDDBdSdXNzaWFuIFRydXN0ZWQgUm9v
dCBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMfFOZ8pUAL3+r2n
qqE0Zp52selXsKGFYoG0GM5bwz1bSFtCt+AZQMhkWQheI3poZAToYJu69pHLKS6Q
XBiwBC1cvzYmUYKMYZC7jE5YhEU2bSL0mX7NaMxMDmH2/NwuOVRj8OImVa5s1F4U
zn4Kv3PFlDBjjSjXKVY9kmjUBsXQrIHeaqmUIsPIlNWUnimXS0I0abExqkbdrXbX
YwCOXhOO2pDUx3ckmJlCMUGacUTnylyQW2VsJIyIGA8V0xzdaeUXg0VZ6ZmNUr5Y
Ber/EAOLPb8NYpsAhJe2mXjMB/J9HNsoFMBFJ0lLOT/+dQvjbdRZoOT8eqJpWnVD
U+QL/qEZnz57N88OWM3rabJkRNdU/Z7x5SFIM9FrqtN8xewsiBWBI0K6XFuOBOT
D4V08o4TzJ8+Ccq5XlCUW2L48pZNCYuBDfBh7FxkB7qDgGDiaftEkZZfApRg2E+M
9G8wkNKTPLDc4wH0FDTijhgxR3Y4PiS1HL2Zhw7bD3CbslmEGgfnnZojNkJtcLeB
HBLa52/dSwNU4WWLubaYSiAmA9IUMX1/RpfpxOxd4YkmhZ97oFbUaDJFipIggx5s
XePAlkTdWnv+RWBxlJwMQ25oEHmRguNYf4Zr/Rxr9cS93Y+mdXIZaBEE0KS2iLRq
aOiWBki9IMQU4phqPOBAaG7A+eP8PAgMBAAGjZjBkMB0GA1UdDgQWBBTh0YHlzlpf
BKrS6badZrHF+qwshzAfBgNVHSMEGDAWgBTh0YHlzlpfBKrS6badZrHF+qwshzAS
BgNVHRMBAf8ECDAGAQH/AgEEMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsF
AAOCAgEAALIY1wkilt/urfEVM5vKzr6utOeDWCUczmWX/RX4ljpRdgF+5fAIS4vH
tmXkqpSCOVeWUrJV9QvZn6L227ZwuE15cWi8DCDal3Ue90WgAJJZMfTshN4OI8cq
W9E4EG9wglbEtMnObHlms8F3CHmrw3k6KmUkWGoa+/ENmcVl68u/cMRl1JbW2bM+
/3A+SAg2c6iPDlehczKx2oa95QW0SkPPWGuNA/CE8CpyANIhu9XFrj3RQ3EqeRcS
AQQod1RNuHpfETLU/A2gMmvn/w/sx7TB3W5BPs6rprOA37tutPq9u6FTZOcG1Oqj
C/B7yTqgI7rbyvox7DEXoX7rIiEqyNNUguTk/u3SZ4VXE2kmxdmSh3TQvybfbnXV
4JbCZVaqiZraqc7oZMnRoWrXRG3ztbnbes/9qhRGI7PqXqeKJBztxRTEVj8ONs1d
WN5szTwaPIvhkhO3CO5ErU2rVdUr89wKpNXbBODFKRtgxUT70YpmJ46VVaqdAhOZ
D9EUUn4YaeLaS8AjSF/h7UkjOibNc4qVDiPP+rkehFWM66PVnP1Msh93tc+taIfC
EYVMxjh8zNbFuoc7fzvvrFILLe7ifvEIUqSVIC/AzplM/Jxw7buXFeGP1qVCBEHq
391d/9RAfaZ12zkwFsl+IKwE/OZxW8AHa9i1p4GO0YSNuczzEm4=
-----END CERTIFICATE-----`;

const RUSSIAN_SUB_CA = `-----BEGIN CERTIFICATE-----
MIIHQjCCBSqgAwIBAgICEAIwDQYJKoZIhvcNAQELBQAwcDELMAkGA1UEBhMCUlUx
PzA9BgNVBAoMNlRoZSBNaW5pc3RyeSBvZiBEaWdpdGFsIERldmVsb3BtZW50IGFu
ZCBDb21tdW5pY2F0aW9uczEgMB4GA1UEAwwXUnVzc2lhbiBUcnVzdGVkIFJvb3Qg
Q0EwHhcNMjIwMzAyMTEyNTE5WhcNMjcwMzA2MTEyNTE5WjBvMQswCQYDVQQGEwJS
VTE/MD0GA1UECgw2VGhlIE1pbmlzdHJ5IG9mIERpZ2l0YWwgRGV2ZWxvcG1lbnQg
YW5kIENvbW11bmljYXRpb25zMR8wHQYDVQQDDBZSdXNzaWFuIFRydXN0ZWQgU3Vi
IENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA9YPqBKOk19NFymrE
wehzrhBEgT2atLezpduB24mQ7CiOa/HVpFCDRZzdxqlh8drku408/tTmWzlNH/br
HuQhZ/miWKOf35lpKzjyBd6TPM23uAfJvEOQ2/dnKGGJbsUo1/udKSvxQwVHpVv3
S80OlluKfhWPDEXQpgyFqIzPoxIQTLZ0deirZwMVHarZ5u8HqHetRuAtmO2ZDGQn
vVOJYAjls+Hiueq7Lj7Oce7CQsTwVZeP+XQx28PAaEZ3y6sQEt6rL06ddpSdoTMp
BnCqTbxW+eWMyjkIn6t9GBtUV45yB1EkHNnj2Ex4GwCiN9T84QQjKSr+8f0psGrZ
vPbCbQAwNFJjisLixnjlGPLKa5vOmNwIh/LAyUW5DjpkCx004LPDuqPpFsKXNKpa
L2Dm6uc0x4Jo5m+gUTVORB6hOSzWnWDj2GWfomLzzyjG81DRGFBpco/O93zecsIN
3SL2Ysjpq1zdoS01CMYxie//9zWvYwzI25/OZigtnpCIrcd2j1Y6dMUFQAzAtHE+
qsXflSL8HIS+IJEFIQobLlYhHkoE3avgNx5jlu+OLYe0dF0Ykx1PGNjbwqvTX37R
Cn32NMjlotW2QcGEZhDKj+3urZizp5xdTPZitA+aEjZM/Ni71VOdiOP0igbw6asZ
2fxdozZ1TnSSYNYvNATwthNmZysCAwEAAaOCAeUwggHhMBIGA1UdEwEB/wQIMAYB
Af8CAQAwDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBTR4XENCy2BTm6KSo9MI7NM
XqtpCzAfBgNVHSMEGDAWgBTh0YHlzlpfBKrS6badZrHF+qwshzCBxwYIKwYBBQUH
AQEEgbowgbcwOwYIKwYBBQUHMAKGL2h0dHA6Ly9yb3N0ZWxlY29tLnJ1L2NkcC9y
b290Y2Ffc3NsX3JzYTIwMjIuY3J0MDsGCCsGAQUFBzAChi9odHRwOi8vY29tcGFu
eS5ydC5ydS9jZHAvcm9vdGNhX3NzbF9yc2EyMDIyLmNydDA7BggrBgEFBQcwAoYv
aHR0cDovL3JlZXN0ci1wa2kucnUvY2RwL3Jvb3RjYV9zc2xfcnNhMjAyMi5jcnQw
gbAGA1UdHwSBqDCBpTA1oDOgMYYvaHR0cDovL3Jvc3RlbGVjb20ucnUvY2RwL3Jv
b3RjYV9zc2xfcnNhMjAyMi5jcmwwNaAzoDGGL2h0dHA6Ly9jb21wYW55LnJ0LnJ1
L2NkcC9yb290Y2Ffc3NsX3JzYTIwMjIuY3JsMDWgM6Axhi9odHRwOi8vcmVlc3Ry
LXBraS5ydS9jZHAvcm9vdGNhX3NzbF9yc2EyMDIyLmNybDANBgkqhkiG9w0BAQsF
AAOCAgEARBVzZls79AdiSCpar15dA5Hr/rrT4WbrOfzlpI+xrLeRPrUG6eUWIW4v
Sui1yx3iqGLCjPcKb+HOTwoRMbI6ytP/ndp3TlYua2advYBEhSvjs+4vDZNwXr/D
anbwIWdurZmViQRBDFebpkvnIvru/RpWud/5r624Wp8voZMRtj/cm6aI9LtvBfT9
cfzhOaexI/99c14dyiuk1+6QhdwKaCRTc1mdfNQmnfWNRbfWhWBlK3h4GGE9JK33
Gk8ZS8DMrkdAh0xby4xAQ/mSWAfWrBmfzlOqGyoB1U47WTOeqNbWkkoAP2ys94+s
Jg4NTkiDVtXRF6nr6fYi0bSOvOFg0IQrMXO2Y8gyg9ARdPJwKtvWX8VPADCYMiWH
h4n8bZokIrImVKLDQKHY4jCsND2HHdJfnrdL2YJw1qFskNO4cSNmZydw0Wkgjv9k
F+KxqrDKlB8MZu2Hclph6v/CZ0fQ9YuE8/lsHZ0Qc2HyiSMnvjgK5fDc3TD4fa8F
E8gMNurM+kV8PT8LNIM+4Zs+LKEV8nqRWBaxkIVJGekkVKO8xDBOG/aN62AZKHOe
GcyIdu7yNMMRihGVZCYr8rYiJoKiOzDqOkPkLOPdhtVlgnhowzHDxMHND/E2WA5p
ZHuNM/m0TXt2wTTPL7JH2YC0gPz/BvvSzjksgzU5rLbRyUKQkgU=
-----END CERTIFICATE-----`;

// Inject Russian CAs into Node.js TLS globally
const _origCreateSecureContext = tls.createSecureContext;
tls.createSecureContext = function(options) {
  const ctx = _origCreateSecureContext.call(tls, options);
  try { ctx.context.addCACert(RUSSIAN_ROOT_CA); } catch(e) {}
  try { ctx.context.addCACert(RUSSIAN_SUB_CA); } catch(e) {}
  return ctx;
};
console.log('🔐 Russian Trusted CA loaded');

// Russian DNS resolver (Yandex 77.88.8.8)
const ruDns = new Resolver();
ruDns.setServers(['77.88.8.8', '77.88.8.1']);

async function resolveRuDomain(hostname) {
  if (hostname.endsWith('.ru') || hostname.endsWith('.su') || hostname.endsWith('.рф')) {
    try {
      const addrs = await ruDns.resolve4(hostname);
      if (addrs.length) { console.log(`  🇷🇺 DNS: ${hostname} → ${addrs[0]}`); return addrs[0]; }
    } catch(e) { console.log(`  ⚠ RuDNS fail: ${hostname}: ${e.message}`); }
  }
  return null;
}

const CORS = { 'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'GET,POST,OPTIONS','Access-Control-Allow-Headers':'Content-Type','Access-Control-Max-Age':'86400' };
function json(res,d,s=200){res.writeHead(s,{...CORS,'Content-Type':'application/json'});res.end(JSON.stringify(d))}

// TCP/SOCKS tests
function tcpTest(h,p,t=7000){return new Promise(r=>{const t0=Date.now(),s=new net.Socket();s.setTimeout(t);s.on('connect',()=>{s.destroy();r({status:'alive',latency:Date.now()-t0})});s.on('timeout',()=>{s.destroy();r({status:'dead',latency:Date.now()-t0,error:'timeout'})});s.on('error',e=>{s.destroy();r({status:e.code==='ECONNREFUSED'?'alive':'dead',latency:Date.now()-t0,error:e.message})});s.connect(parseInt(p),h)})}
function socksTest(h,p,v=5,t=8000){return new Promise(r=>{const t0=Date.now(),s=new net.Socket();s.setTimeout(t);s.on('connect',()=>{if(v===5)s.write(Buffer.from([5,1,0]));else{const b=Buffer.alloc(9);b[0]=4;b[1]=1;b.writeUInt16BE(80,2);b[7]=1;b[8]=0;s.write(b)}});s.on('data',d=>{s.destroy();const ms=Date.now()-t0;if(v===5&&d.length>=2&&d[0]===5)r({status:'alive',latency:ms,detail:`SOCKS5(auth:${d[1]})`});else if(v===4&&d.length>=2&&d[0]===0)r({status:'alive',latency:ms,detail:'SOCKS4 OK'});else r({status:'alive',latency:ms,detail:'Port open'})});s.on('timeout',()=>{s.destroy();r({status:'dead',latency:Date.now()-t0,error:'timeout'})});s.on('error',e=>{s.destroy();r({status:'dead',latency:Date.now()-t0,error:e.message})});s.connect(parseInt(p),h)})}

// Fetch with got-scraping + Russian DNS + Russian CA
async function fetchThrough(targetUrl, proxyUrl, timeout=25000) {
  const t0 = Date.now();
  const parsed = new URL(targetUrl);
  const resolvedIp = await resolveRuDomain(parsed.hostname);

  const opts = {
    url: targetUrl,
    headerGeneratorOptions: { browsers:['chrome'], operatingSystems:['windows'], locales:['ru-RU,ru;q=0.9','en-US,en;q=0.8'] },
    headers: { 'Accept-Language':'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7' },
    https: { ciphers:'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256', rejectUnauthorized:false },
    http2:true, decompress:true, followRedirect:true, maxRedirects:5,
    timeout:{request:timeout}, retry:{limit:0}, responseType:'text',
  };

  if (proxyUrl) {
    const lower = proxyUrl.toLowerCase();
    if (lower.startsWith('socks')) {
      // SOCKS proxies need SocksProxyAgent — got-scraping v4 doesn't support socks:// natively
      const agent = new SocksProxyAgent(proxyUrl);
      opts.agent = { http: agent, https: agent };
      // Disable http2 when using SOCKS agent (not compatible)
      opts.http2 = false;
      console.log(`  🔗 SOCKS Proxy: ${proxyUrl} (via SocksProxyAgent)`);
      console.log('  🇷🇺 SOCKS remote DNS active');
    } else {
      opts.proxyUrl = proxyUrl;
      console.log(`  🔗 HTTP Proxy: ${proxyUrl}`);
    }
  } else if (resolvedIp) {
    // Direct fetch with Russian DNS resolved IP
    opts.url = targetUrl.replace(parsed.hostname, resolvedIp);
    opts.headers['Host'] = parsed.hostname;
    console.log(`  🇷🇺 IP: ${resolvedIp} Host: ${parsed.hostname}`);
  }

  console.log(`  🌐 → ${opts.url}`);
  const r = await gotScraping(opts);
  const body = typeof r.body === 'string' ? r.body : r.body.toString('utf-8');
  console.log(`  ✓ ${r.statusCode} (${Date.now()-t0}ms, ${Math.round(body.length/1024)}KB)`);
  return { status:r.statusCode, headers:r.headers, body, latency:Date.now()-t0 };
}

// Server
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  if (req.method==='OPTIONS'){res.writeHead(204,CORS);res.end();return}

  if (url.pathname==='/health') return json(res,{status:'ok',type:'render-v3-ruca',features:['socks5','russian-ca','russian-dns','h2','tls-fp'],time:new Date().toISOString()});

  if (url.pathname==='/test') {
    const host=url.searchParams.get('host'),port=url.searchParams.get('port')||'80',proto=(url.searchParams.get('proto')||'http').toLowerCase();
    if(!host)return json(res,{error:'Missing host'},400);
    const pa=`${proto}://${host}:${port}`;console.log(`🔍 Test: ${pa}`);const t0=Date.now();
    for(const target of ['http://httpbin.org/ip','http://ip-api.com/json','http://ifconfig.me/ip']){
      try{console.log(`  → ${target} via ${pa}`);
        const testOpts = {url:target,timeout:{request:12000},retry:{limit:0},http2:false,followRedirect:true,responseType:'text',https:{rejectUnauthorized:false}};
        if (proto.startsWith('socks')) {
          const agent = new SocksProxyAgent(pa);
          testOpts.agent = { http: agent, https: agent };
        } else {
          testOpts.proxyUrl = pa;
        }
        const r=await gotScraping(testOpts);
        let ip='';try{const b=r.body;if(b.includes('"origin"'))ip=JSON.parse(b).origin;else if(b.includes('"query"'))ip=JSON.parse(b).query;else ip=b.trim().split('\n')[0].substring(0,45)}catch{}
        console.log(`  ✓ ALIVE ${Date.now()-t0}ms exit:${ip||'?'}`);
        return json(res,{host,port:+port,proto,status:'alive',latency:Date.now()-t0,detail:`HTTP ${r.statusCode}`,exitIp:ip||null});
      }catch(e){console.log(`  ⚠ ${e.message}`)}}
    let r;if(proto.includes('socks5'))r=await socksTest(host,port,5);else if(proto==='socks4')r=await socksTest(host,port,4);else r=await tcpTest(host,port);
    return json(res,{host,port:+port,proto,...r});
  }

  if (url.pathname==='/fetch') {
    const targetUrl=url.searchParams.get('url'),proxyUrl=url.searchParams.get('proxy')||null;
    if(!targetUrl)return json(res,{error:'Missing url'},400);
    console.log(`🌐 Fetch: ${targetUrl}${proxyUrl?' via '+proxyUrl:''}`);
    try{const r=await fetchThrough(targetUrl,proxyUrl);const ct=(r.headers||{})['content-type']||'text/html';
      res.writeHead(r.status||200,{...CORS,'Content-Type':ct,'X-Latency':String(r.latency),'X-Proxy':proxyUrl||'direct'});res.end(r.body);
    }catch(e){console.log(`  ✗ ${e.message}`);json(res,{error:e.message,url:targetUrl,proxy:proxyUrl},502)}
    return;
  }

  res.writeHead(200,{...CORS,'Content-Type':'text/html'});
  res.end('<html><body style="font-family:system-ui;background:#0b0f1a;color:#e8ecf4;display:flex;align-items:center;justify-content:center;height:100vh;margin:0"><div style="text-align:center"><h1 style="color:#60a5fa">⚡ TunnelX v3</h1><p style="color:#94a3b8">SOCKS5 + Russian CA + Russian DNS</p></div></body></html>');
});

server.listen(PORT, () => {
  console.log(`\n  ⚡ TunnelX Relay v3 — port ${PORT}`);
  console.log('  🔐 Russian CA ✓  🇷🇺 Yandex DNS ✓  📡 SOCKS5 remote DNS ✓\n');
});
