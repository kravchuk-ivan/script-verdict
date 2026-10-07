// SSRF-guarded server-side fetch of a remote script.
// - http/https only
// - DNS resolve (all records); reject if any resolves to a blocked range
// - pin the connection to a validated resolved IP (Host header preserved)
// - follow redirects manually (max 3), re-validating each hop
// - 5 s timeout, 5 MB cap

import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';

const TIMEOUT_MS = 5000;
const MAX_BYTES = 5 * 1024 * 1024;
const MAX_REDIRECTS = 3;

function ipv4ToInt(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}

function inRange(int, cidrBase, prefix) {
  const base = ipv4ToInt(cidrBase);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (int & mask) === (base & mask);
}

const V4_BLOCKS = [
  ['0.0.0.0', 8],       // this network
  ['10.0.0.0', 8],      // private
  ['100.64.0.0', 10],   // CGNAT
  ['127.0.0.0', 8],     // loopback
  ['169.254.0.0', 16],  // link-local
  ['172.16.0.0', 12],   // private
  ['192.0.0.0', 24],    // IETF protocol assignments
  ['192.0.2.0', 24],    // TEST-NET-1
  ['192.168.0.0', 16],  // private
  ['198.18.0.0', 15],   // benchmark
  ['198.51.100.0', 24], // TEST-NET-2
  ['203.0.113.0', 24],  // TEST-NET-3
  ['224.0.0.0', 4],     // multicast
  ['240.0.0.0', 4],     // reserved
];

function isBlockedV4(ip) {
  const int = ipv4ToInt(ip);
  if (int === null) return true;
  if (int === 0xffffffff) return true; // broadcast
  return V4_BLOCKS.some(([base, prefix]) => inRange(int, base, prefix));
}

// Expand an IPv6 string to 16 bytes. Returns null on parse failure.
function ipv6ToBytes(ip) {
  let s = ip;
  // strip zone id
  const pct = s.indexOf('%');
  if (pct !== -1) s = s.slice(0, pct);
  let embeddedV4 = null;
  const lastColon = s.lastIndexOf(':');
  const tail = s.slice(lastColon + 1);
  if (tail.includes('.')) {
    embeddedV4 = ipv4ToInt(tail);
    if (embeddedV4 === null) return null;
    s = s.slice(0, lastColon + 1) + '0:0';
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tailParts = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  let groups;
  if (halves.length === 2) {
    const missing = 8 - head.length - tailParts.length;
    if (missing < 0) return null;
    groups = [...head, ...Array(missing).fill('0'), ...tailParts];
  } else {
    groups = head;
  }
  if (groups.length !== 8) return null;
  const bytes = [];
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    const v = parseInt(g, 16);
    bytes.push((v >> 8) & 0xff, v & 0xff);
  }
  if (embeddedV4 !== null) {
    bytes[12] = (embeddedV4 >>> 24) & 0xff;
    bytes[13] = (embeddedV4 >>> 16) & 0xff;
    bytes[14] = (embeddedV4 >>> 8) & 0xff;
    bytes[15] = embeddedV4 & 0xff;
  }
  return bytes;
}

function isBlockedV6(ip) {
  const b = ipv6ToBytes(ip);
  if (!b) return true;
  // unspecified ::
  if (b.every((x) => x === 0)) return true;
  // loopback ::1
  if (b.slice(0, 15).every((x) => x === 0) && b[15] === 1) return true;
  // multicast ff00::/8
  if (b[0] === 0xff) return true;
  // link-local fe80::/10
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return true;
  // ULA fc00::/7
  if ((b[0] & 0xfe) === 0xfc) return true;
  // IPv4-mapped ::ffff:0:0/96 and IPv4-compatible ::/96 -> check embedded v4
  const first10Zero = b.slice(0, 10).every((x) => x === 0);
  if (first10Zero && ((b[10] === 0xff && b[11] === 0xff) || (b[10] === 0 && b[11] === 0))) {
    const v4 = `${b[12]}.${b[13]}.${b[14]}.${b[15]}`;
    return isBlockedV4(v4);
  }
  // NAT64 64:ff9b::/96
  if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b) {
    const v4 = `${b[12]}.${b[13]}.${b[14]}.${b[15]}`;
    return isBlockedV4(v4);
  }
  // 6to4 2002::/16 -> extract embedded v4 (bytes 2..5)
  if (b[0] === 0x20 && b[1] === 0x02) {
    const v4 = `${b[2]}.${b[3]}.${b[4]}.${b[5]}`;
    return isBlockedV4(v4);
  }
  return false;
}

export function isBlockedIp(ip) {
  const fam = net.isIP(ip);
  if (fam === 4) return isBlockedV4(ip);
  if (fam === 6) return isBlockedV6(ip);
  return true; // not a literal IP
}

async function resolveAndValidate(rawHostname) {
  // URL hostnames for IPv6 literals keep their surrounding brackets, e.g. "[::1]".
  const hostname = rawHostname.startsWith('[') && rawHostname.endsWith(']')
    ? rawHostname.slice(1, -1)
    : rawHostname;
  // literal IP given directly
  const litFam = net.isIP(hostname);
  if (litFam) {
    if (isBlockedIp(hostname)) throw new Error(`Blocked address: ${hostname}`);
    return [{ address: hostname, family: litFam }];
  }
  let records;
  try {
    records = await dns.promises.lookup(hostname, { all: true });
  } catch {
    throw new Error(`DNS resolution failed for ${hostname}`);
  }
  if (!records.length) throw new Error(`No DNS records for ${hostname}`);
  for (const r of records) {
    if (isBlockedIp(r.address)) throw new Error(`${hostname} resolves to blocked address ${r.address}`);
  }
  return records;
}

function requestOnce(targetUrl, pinnedIp, family) {
  return new Promise((resolve, reject) => {
    const isHttps = targetUrl.protocol === 'https:';
    const lib = isHttps ? https : http;
    const options = {
      host: pinnedIp,
      servername: isHttps ? targetUrl.hostname : undefined,
      port: targetUrl.port || (isHttps ? 443 : 80),
      path: targetUrl.pathname + targetUrl.search,
      method: 'GET',
      family,
      headers: {
        Host: targetUrl.host,
        'User-Agent': 'ScriptSecurityAnalyzer/2.0 (+ssrf-guarded)',
        Accept: '*/*',
      },
      timeout: TIMEOUT_MS,
    };
    const req = lib.request(options, (res) => {
      resolve(res);
    });
    req.on('timeout', () => { req.destroy(new Error('Request timed out')); });
    req.on('error', reject);
    req.end();
  });
}

// Fetch a URL safely. Returns { script, source, bytes }.
export async function safeFetch(rawUrl) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error('Invalid URL');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('Only http and https URLs are allowed');
  }

  let current = url;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const records = await resolveAndValidate(current.hostname);
    const pinned = records[0];
    const res = await requestOnce(current, pinned.address, pinned.family);

    // redirects
    if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
      res.resume(); // drain
      if (hop === MAX_REDIRECTS) throw new Error('Too many redirects');
      let next;
      try {
        next = new URL(res.headers.location, current);
      } catch {
        throw new Error('Invalid redirect location');
      }
      if (next.protocol !== 'http:' && next.protocol !== 'https:') {
        throw new Error('Redirect to non-http(s) URL blocked');
      }
      current = next;
      continue;
    }

    if (res.statusCode < 200 || res.statusCode >= 300) {
      res.resume();
      throw new Error(`Upstream returned HTTP ${res.statusCode}`);
    }

    // read body with cap
    const chunks = [];
    let size = 0;
    return await new Promise((resolve, reject) => {
      res.on('data', (c) => {
        size += c.length;
        if (size > MAX_BYTES) {
          req_destroy(res);
          reject(new Error('Response exceeds 5 MB limit'));
        } else {
          chunks.push(c);
        }
      });
      res.on('end', () => {
        resolve({ script: Buffer.concat(chunks).toString('utf8'), source: current.href, bytes: size });
      });
      res.on('error', reject);
    });
  }
  throw new Error('Too many redirects');
}

function req_destroy(res) {
  try { res.destroy(); } catch {}
}
