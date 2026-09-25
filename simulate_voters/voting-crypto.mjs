// voting-crypto.mjs
//
// 從 voter_client/voter-crypto.js（瀏覽器端原始碼）移植過來的密碼學工具集，
// 拿掉所有跟 DOM / IndexedDB 相關的部分，改成純函式，讓 Node.js 腳本可以
// 在沒有瀏覽器的情況下，執行完全相同的一套「生成金鑰 → PoP → 盲簽章 →
// 數位信封」流程，用來做大量選民的投票模擬測試。
//
// Node 18+ 才有原生的 global fetch / crypto.subtle / atob / btoa，
// 請確認 `node --version` >= 18（本專案開發時用的是 v26，沒問題）。

/* ---------- PEM / DER / Bytes ---------- */
export function pemToDer(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
  const str = atob(b64);
  return Uint8Array.from(str, c => c.charCodeAt(0)).buffer;
}
export function derToPem(der, type) {
  const b64 = btoa(String.fromCharCode(...new Uint8Array(der)));
  return `-----BEGIN ${type}-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END ${type}-----`;
}
export function hexToBytes(hex) {
  const h = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;
  const padded = h.length % 2 ? '0' + h : h;
  return new Uint8Array(padded.match(/.{2}/g).map(b => parseInt(b, 16)));
}
export function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
export function hexToBigInt(hex) {
  return BigInt(hex.startsWith('0x') || hex.startsWith('0X') ? hex : '0x' + hex);
}
export function b64encode(bytes) {
  return btoa(String.fromCharCode(...bytes));
}
export function b64decode(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

/* ---------- 最小 DER/ASN.1 解析器（跟 voter-crypto.js 完全一致） ---------- */
function derReadTLV(bytes, offset) {
  const tag = bytes[offset];
  const lenByte = bytes[offset + 1];
  let lenOfLen = 0, length;
  if (lenByte & 0x80) {
    lenOfLen = lenByte & 0x7f;
    length = 0;
    for (let i = 0; i < lenOfLen; i++) length = (length << 8) | bytes[offset + 2 + i];
  } else {
    length = lenByte;
  }
  const headerLen = 2 + lenOfLen;
  const contentStart = offset + headerLen;
  const contentEnd = contentStart + length;
  return { tag, start: offset, end: contentEnd, contentStart, contentEnd };
}
function derChildren(bytes, start, end) {
  const out = [];
  for (let o = start; o < end;) {
    const tlv = derReadTLV(bytes, o);
    out.push(tlv);
    o = tlv.end;
  }
  return out;
}
function derFindOid(bytes, oidValueBytes, start, end) {
  search:
  for (let i = start; i + 2 + oidValueBytes.length <= end; i++) {
    if (bytes[i] !== 0x06 || bytes[i + 1] !== oidValueBytes.length) continue;
    for (let j = 0; j < oidValueBytes.length; j++) {
      if (bytes[i + 2 + j] !== oidValueBytes[j]) continue search;
    }
    return derReadTLV(bytes, derReadTLV(bytes, i).end);
  }
  return null;
}
export function parseCertificate(certPem) {
  const der = new Uint8Array(pemToDer(certPem));
  const top = derReadTLV(der, 0);
  const [tbs, , sigValTlv] = derChildren(der, top.contentStart, top.contentEnd);
  const sigValue = der.slice(sigValTlv.contentStart + 1, sigValTlv.contentEnd);
  const tbsBytes = der.slice(tbs.start, tbs.end);
  let tbsChildren = derChildren(der, tbs.contentStart, tbs.contentEnd);
  if (tbsChildren[0].tag === 0xa0) tbsChildren = tbsChildren.slice(1);
  const subjectTlv = tbsChildren[4];
  const spkiTlv = tbsChildren[5];
  const spkiBytes = der.slice(spkiTlv.start, spkiTlv.end);
  const cnTlv = derFindOid(der, [0x55, 0x04, 0x03], subjectTlv.contentStart, subjectTlv.contentEnd);
  const commonName = cnTlv ? new TextDecoder().decode(der.slice(cnTlv.contentStart, cnTlv.contentEnd)) : null;
  return { tbsBytes, sigValue, spkiBytes, commonName };
}
export function parseRsaPublicKeyFromSpki(spkiBytes) {
  const top = derReadTLV(spkiBytes, 0);
  const [, bitStrTlv] = derChildren(spkiBytes, top.contentStart, top.contentEnd);
  const rsaPkBytes = spkiBytes.slice(bitStrTlv.contentStart + 1, bitStrTlv.contentEnd);
  const rsaTop = derReadTLV(rsaPkBytes, 0);
  const [nTlv, eTlv] = derChildren(rsaPkBytes, rsaTop.contentStart, rsaTop.contentEnd);
  return {
    n: hexToBigInt(bytesToHex(rsaPkBytes.slice(nTlv.contentStart, nTlv.contentEnd))),
    e: hexToBigInt(bytesToHex(rsaPkBytes.slice(eTlv.contentStart, eTlv.contentEnd))),
  };
}
export async function importOaepKeyFromSpki(spkiBytes) {
  return crypto.subtle.importKey('spki', spkiBytes, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
}
export async function rsaOaepEncryptWithKey(key, plaintext) {
  const data = plaintext instanceof Uint8Array ? plaintext : new TextEncoder().encode(plaintext);
  return b64encode(new Uint8Array(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, key, data)));
}

/* ---------- CA 憑證鏈驗證 ---------- */
export async function importCaVerifyKey(spkiBytes) {
  return crypto.subtle.importKey('spki', spkiBytes, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
}
export async function verifyCertChain(certPem, expectedCN, caPublicKey) {
  if (!certPem) throw new Error(`伺服器未提供 ${expectedCN} 的憑證，無法驗證公鑰來源`);
  const { tbsBytes, sigValue, spkiBytes, commonName } = parseCertificate(certPem);
  if (commonName !== expectedCN) {
    throw new Error(`憑證主體 CN 不符（預期 ${expectedCN}，實際 ${commonName}），拒絕信任此公鑰`);
  }
  const ok = await crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, caPublicKey, sigValue, tbsBytes);
  if (!ok) throw new Error(`${expectedCN} 憑證簽章驗證失敗，可能遭偽造或竄改，拒絕信任此公鑰`);
  return spkiBytes;
}

/* ---------- SHA-256 ---------- */
export async function sha256Bytes(input) {
  const data = typeof input === 'string' ? new TextEncoder().encode(input) : input;
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}
export async function sha256Hex(input) {
  return bytesToHex(await sha256Bytes(input));
}

/* ---------- RSA keypair / 簽章 ---------- */
export async function generateRSAKeypair() {
  return crypto.subtle.generateKey(
    { name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true, ['sign', 'verify']
  );
}
export async function exportPublicKeyPEM(publicKey) {
  return derToPem(await crypto.subtle.exportKey('spki', publicKey), 'PUBLIC KEY');
}
export async function rsaPssSign(privateKey, data) {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const sig = await crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, privateKey, bytes);
  return b64encode(new Uint8Array(sig));
}

/* ---------- AES-256-GCM ---------- */
export async function aesGcmEncrypt(plaintext, aadStr) {
  const k = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = new TextEncoder().encode(aadStr);
  const pt = typeof plaintext === 'string' ? new TextEncoder().encode(plaintext) : plaintext;
  const sk = await crypto.subtle.importKey('raw', k, 'AES-GCM', true, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, sk, pt));
  return {
    k, iv: b64encode(iv), c_data: b64encode(ct.slice(0, -16)),
    tag: b64encode(ct.slice(-16)), aad: b64encode(aad),
  };
}

/* ---------- 大數運算 / 盲簽章 ---------- */
export function modpow(base, exp, mod) {
  let r = 1n; base %= mod;
  for (; exp > 0n; exp >>= 1n) {
    if (exp & 1n) r = r * base % mod;
    base = base * base % mod;
  }
  return r;
}
function modinv(a, m) {
  let [r0, r1, s0, s1] = [a, m, 1n, 0n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  return ((s0 % m) + m) % m;
}
function bigintGcd(a, b) {
  a = a < 0n ? -a : a;
  b = b < 0n ? -b : b;
  while (b) { [a, b] = [b, a % b]; }
  return a;
}
export async function fdh(mBytes, nBits) {
  const target = Math.ceil(nBits / 8);
  const parts = [];
  let len = 0;
  for (let i = 0; len < target; i++) {
    const ctr = new Uint8Array(4);
    new DataView(ctr.buffer).setUint32(0, i, false);
    const h = await sha256Bytes(new Uint8Array([...mBytes, ...ctr]));
    parts.push(h); len += 32;
  }
  const mask = new Uint8Array([].concat(...parts.map(a => [...a]))).slice(0, target);
  const excess = 8 * target - nBits + 1;
  if (excess > 0) mask[0] &= (0xFF >> excess);
  return hexToBigInt(bytesToHex(mask));
}
export function generateBlindingFactor(n) {
  const bytes = new Uint8Array(Math.ceil(n.toString(16).length / 2) + 4);
  let r;
  do {
    crypto.getRandomValues(bytes);
    r = hexToBigInt(bytesToHex(bytes)) % n;
  } while (r <= 1n || bigintGcd(r, n) !== 1n);
  return r;
}
export function blindMessage(mu, r, e, n) { return (mu * modpow(r, e, n)) % n; }
export function unblindSignature(S, r, n) { return (S * modinv(r, n)) % n; }

/* ---------- 認證封包（格式須與 shared/auth_component.py 一致） ---------- */
export async function createAuthPacket(senderId, receiverId, privateKey, certPem, nonceEcho) {
  const nonce = bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
  const ts = Math.floor(Date.now() / 1000);
  const payload = { cert_pem: certPem, nonce, receiver_id: receiverId, sender_id: senderId, timestamp: ts };
  if (nonceEcho) payload.nonce_echo = nonceEcho;
  const sorted = Object.fromEntries(Object.keys(payload).sort().map(k => [k, payload[k]]));
  const jsonStr = JSON.stringify(sorted);
  const sig = await rsaPssSign(privateKey, jsonStr);
  return { payload, signature: sig };
}
