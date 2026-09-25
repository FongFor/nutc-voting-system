#!/usr/bin/env node
// run.mjs — 大量選民分時投票模擬腳本
//
// 用途：建立 N 位模擬選民、依「開頭尖峰、中間平緩、結尾又衝一波」的分佈
// 把他們的投票時間點分散在整個投票開放時間窗內，逐一在各自排定的時間點
// 執行完整的瀏覽器端投票流程（RSA 金鑰生成、PoP、TPA 雙向認證、盲簽章、
// 數位信封封裝、送出）——跟真人用瀏覽器投票走的是完全同一套密碼學協定，
// 只是把 DOM 操作換成純 Node.js 程式。
//
// 設計原則：
//   - 建議在自己的電腦執行，不要在 Oracle 伺服器上跑，避免這支腳本本身
//     的運算（尤其是 RSA 金鑰生成）跟伺服器上的 7 個容器搶資源。
//   - 刻意不限制同時執行數量（照你的需求），但這代表尖峰時段真的會有
//     大量並發請求打進伺服器，記得開一個視窗跑 monitor.sh 觀察狀況，
//     真的扛不住就直接 Ctrl+C 中止這支腳本。
//
// 用法：
//   node run.mjs
//
// 執行前請先確認下面 CONFIG 區塊的網址、人數、時間窗設定是否正確。

import { writeFileSync, appendFileSync, existsSync } from 'node:fs';
import * as vcrypto from './voting-crypto.mjs';

// ============================================================
// CONFIG —— 執行前請依實際狀況調整
// ============================================================
const CONFIG = {
  // 選民實際會連的公開投票網址（Caddy 反向代理後面那個網域）
  VOTER_URL: 'https://nutc-vote.accesscam.org',

  // Admin 後台網址——用 Tailscale 就填 https://<tailscale-ip>:5011，
  // 用 SSH tunnel 就填 https://localhost:5010（tunnel 要保持連著）
  ADMIN_URL: 'https://100.97.156.121:5011',

  // Admin 用的是自簽憑證（不是 Let's Encrypt），Node 預設會拒絕，
  // 這個開關只在呼叫 ADMIN_URL 那幾支請求時暫時關閉憑證驗證。
  ADMIN_SELF_SIGNED: true,

  NUM_VOTERS: 1000,
  VOTER_ID_PREFIX: 'SIM',          // 產生的學號會長這樣：SIM0001, SIM0002...

  // 投票開放時間窗長度（秒），要跟 config.json 的 vote_duration_seconds
  // 一致，否則排到窗口外的投票會在送出時被拒絕（DEADLINE_PASSED）。
  ELECTION_WINDOW_SECONDS: 86400,

  // 「開頭尖峰、中間平緩、結尾又衝一波」的分佈參數：
  //   pStart / pEnd：落在開頭／結尾尖峰的人數比例，剩下 1-pStart-pEnd 落在中間平緩段
  //   tauFraction：尖峰的「陡峭程度」，乘上時間窗長度得到衰減時間常數，
  //                數字越小尖峰越集中在窗口邊緣，越大尖峰拖得越長
  DIST: { pStart: 0.35, pEnd: 0.35, tauFraction: 0.03 },

  // 批次新增選民時，每批幾筆、批次間間隔多久（避免瞬間灌爆 admin）
  BATCH_ADD_CHUNK_SIZE: 50,
  BATCH_ADD_DELAY_MS: 800,

  LOG_FILE: './simulate_voters_log.jsonl',
};

// ============================================================
// 工具
// ============================================================
function log(msg) {
  console.log(`[${new Date().toISOString()}] ${msg}`);
}
function appendLog(record) {
  appendFileSync(CONFIG.LOG_FILE, JSON.stringify(record) + '\n');
}
function sleep(ms) {
  return new Promise(res => setTimeout(res, ms));
}

/** 在 ADMIN_URL 呼叫時暫時關閉 TLS 憑證驗證（僅限自簽憑證的 admin）。 */
async function fetchAdmin(path, options = {}) {
  const prev = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  if (CONFIG.ADMIN_SELF_SIGNED) process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  try {
    return await fetch(CONFIG.ADMIN_URL + path, options);
  } finally {
    if (prev === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    else process.env.NODE_TLS_REJECT_UNAUTHORIZED = prev;
  }
}

// ============================================================
// 第一階段：批次建立選民 + 取得 OTP
// ============================================================
async function createVoters(n) {
  const voterIds = Array.from({ length: n }, (_, i) => `${CONFIG.VOTER_ID_PREFIX}${String(i + 1).padStart(4, '0')}`);

  log(`開始批次新增 ${n} 位選民（每批 ${CONFIG.BATCH_ADD_CHUNK_SIZE} 筆）...`);
  for (let i = 0; i < voterIds.length; i += CONFIG.BATCH_ADD_CHUNK_SIZE) {
    const chunk = voterIds.slice(i, i + CONFIG.BATCH_ADD_CHUNK_SIZE);
    const resp = await fetchAdmin('/api/add_batch', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ voter_ids: chunk }),
    });
    const data = await resp.json();
    const ok = (data.results || []).filter(r => r.status === 'success').length;
    log(`  批次 ${i / CONFIG.BATCH_ADD_CHUNK_SIZE + 1}：${ok}/${chunk.length} 成功`);
    await sleep(CONFIG.BATCH_ADD_DELAY_MS);
  }

  log('新增完成，向 /print 撈取明文 OTP...');
  const printResp = await fetchAdmin('/print');
  const html = await printResp.text();
  const otpMap = new Map();
  const cardRe = /<div class="voter-id">([^<]+)<\/div>[\s\S]*?<div class="otp-value">([^<]+)<\/div>/g;
  let m;
  while ((m = cardRe.exec(html)) !== null) {
    otpMap.set(m[1].trim(), m[2].trim());
  }

  const voters = voterIds.map(id => ({ voterId: id, otp: otpMap.get(id) })).filter(v => v.otp);
  log(`成功取得 ${voters.length}/${voterIds.length} 位選民的 OTP。`);
  if (voters.length < voterIds.length) {
    log('警告：部分選民沒撈到 OTP（可能新增失敗，或名冊裡有同名舊資料），只會模擬撈得到的這些人。');
  }
  return voters;
}

// ============================================================
// 第二階段：排程——把每位選民分配一個投票時間點
//   開頭尖峰 + 中間平緩 + 結尾尖峰的混合分佈
// ============================================================
function assignVoteOffsets(voters, windowSeconds, dist) {
  const tau = windowSeconds * dist.tauFraction;
  return voters.map(v => {
    const roll = Math.random();
    let offset;
    if (roll < dist.pStart) {
      // 開頭尖峰：指數衰減，越接近 0 密度越高
      offset = -tau * Math.log(1 - Math.random());
    } else if (roll < dist.pStart + dist.pEnd) {
      // 結尾尖峰：鏡像指數衰減，越接近截止時間密度越高
      offset = windowSeconds - (-tau * Math.log(1 - Math.random()));
    } else {
      // 中間平緩段：均勻分布在整個時間窗
      offset = Math.random() * windowSeconds;
    }
    offset = Math.min(Math.max(offset, 0), windowSeconds - 1);
    return { ...v, offsetSeconds: offset };
  }).sort((a, b) => a.offsetSeconds - b.offsetSeconds);
}

// ============================================================
// 第三階段：單一選民的完整投票流程（跟瀏覽器端邏輯一致）
// ============================================================
let _caPublicKeyPromise = null;
function getCaPublicKey() {
  if (!_caPublicKeyPromise) {
    _caPublicKeyPromise = (async () => {
      const r = await fetch(`${CONFIG.VOTER_URL}/api/proxy/ca/ca_cert`).then(x => x.json());
      if (r.status !== 'success' || !r.ca_certificate) throw new Error('無法取得 CA 根憑證：' + (r.message || ''));
      const { spkiBytes } = vcrypto.parseCertificate(r.ca_certificate);
      return vcrypto.importCaVerifyKey(spkiBytes);
    })();
  }
  return _caPublicKeyPromise;
}

async function registerVoter(voterId, otp) {
  const keypair = await vcrypto.generateRSAKeypair();
  const pubPEM = await vcrypto.exportPublicKeyPEM(keypair.publicKey);

  const ts = Math.floor(Date.now() / 1000);
  const challenge = `REGISTER|${voterId}|${ts}`;
  const popSig = await vcrypto.rsaPssSign(keypair.privateKey, challenge);

  const resp = await fetch(`${CONFIG.VOTER_URL}/api/proxy/ca/issue_cert`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ entity_id: voterId, public_key: pubPEM, otp, timestamp: ts, pop_signature: popSig }),
  });
  const data = await resp.json();
  if (data.status !== 'success') throw new Error('註冊失敗：' + (data.message || data.code || ''));

  return { privateKey: keypair.privateKey, certPem: data.certificate };
}

async function castVote(voterId, privateKey, certPem, candidate) {
  const [tpaR, ccR, taR] = await Promise.all([
    fetch(`${CONFIG.VOTER_URL}/api/proxy/tpa/public_key`).then(r => r.json()),
    fetch(`${CONFIG.VOTER_URL}/api/proxy/cc/public_key`).then(r => r.json()),
    fetch(`${CONFIG.VOTER_URL}/api/proxy/ta/public_key`).then(r => r.json()),
  ]);
  if (tpaR.status !== 'success') throw new Error('無法取得 TPA 公鑰：' + (tpaR.message || ''));
  if (ccR.status !== 'success') throw new Error('無法取得 CC 公鑰：' + (ccR.message || ''));
  if (taR.status !== 'success') throw new Error('無法取得 TA 公鑰：' + (taR.message || ''));

  const caPubKey = await getCaPublicKey();
  const tpaSpki = await vcrypto.verifyCertChain(tpaR.cert_pem, 'TPA', caPubKey);
  const ccSpki = await vcrypto.verifyCertChain(ccR.cert_pem, 'CC', caPubKey);
  const taSpki = await vcrypto.verifyCertChain(taR.cert_pem, 'TA', caPubKey);
  const { e: tpa_e, n: tpa_n } = vcrypto.parseRsaPublicKeyFromSpki(tpaSpki);
  const cc_key = await vcrypto.importOaepKeyFromSpki(ccSpki);
  const ta_key = await vcrypto.importOaepKeyFromSpki(taSpki);

  const authPkt = await vcrypto.createAuthPacket(voterId, 'TPA', privateKey, certPem);
  const authResp = await fetch(`${CONFIG.VOTER_URL}/api/proxy/tpa/auth`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ auth_packet: authPkt, voter_cert_pem: certPem }),
  });
  const authData = await authResp.json();
  if (authData.status !== 'success') throw new Error('TPA 認證失敗：' + (authData.message || authData.code || ''));

  const votingToken = authData.voting_token;
  if (!votingToken) throw new Error('TPA 未核發 Voting Token');

  const sn = 'SN' + Date.now() + (voterId.slice(-3) || '000');
  const innerHash = await vcrypto.sha256Hex(voterId + '|' + sn + '|' + candidate);
  const outerHash = await vcrypto.sha256Hex(innerHash + '|' + candidate);
  const m_hex = outerHash;
  const m_bytes = vcrypto.hexToBytes(m_hex);

  const nBits = tpa_n.toString(2).length;
  const mu = await vcrypto.fdh(m_bytes, nBits);
  const r = vcrypto.generateBlindingFactor(tpa_n);
  const m_prime = vcrypto.blindMessage(mu, r, tpa_e, tpa_n);
  const m_prime_hex = '0x' + m_prime.toString(16);

  const signResp = await fetch(`${CONFIG.VOTER_URL}/api/proxy/tpa/blind_sign`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ m_prime_hex, voting_token: votingToken }),
  });
  const signData = await signResp.json();
  if (signData.status !== 'success') throw new Error('盲簽章失敗：' + (signData.message || signData.code || ''));
  const S_int = vcrypto.hexToBigInt(signData.S_hex);

  const S_prime = vcrypto.unblindSignature(S_int, r, tpa_n);
  const mu_check = await vcrypto.fdh(m_bytes, nBits);
  if (vcrypto.modpow(S_prime, tpa_e, tpa_n) !== mu_check) throw new Error('盲簽章本地驗證失敗');
  const s_prime_hex = '0x' + S_prime.toString(16);

  const inner_enc_b64 = await vcrypto.rsaOaepEncryptWithKey(ta_key, innerHash + '|' + candidate);
  const aes_pt = inner_enc_b64 + '|' + s_prime_hex + '|' + m_hex;
  const aad_nonce = vcrypto.bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
  const aad_str = 'voting-system-v2|' + aad_nonce;
  const { k, c_data, iv, tag, aad } = await vcrypto.aesGcmEncrypt(aes_pt, aad_str);
  const c_key = await vcrypto.rsaOaepEncryptWithKey(cc_key, k);
  const token_hash = await vcrypto.sha256Hex(votingToken.payload.token_id);
  const envelope = { c_data, iv, tag, aad, c_key, token_hash };

  const submitResp = await fetch(`${CONFIG.VOTER_URL}/api/submit_envelope`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(envelope),
  });
  const submitData = await submitResp.json();
  if (submitData.status !== 'queued') throw new Error('信封提交失敗：' + (submitData.message || submitData.code || ''));

  return { m_hex, candidate };
}

async function getCandidates() {
  const r = await fetch(`${CONFIG.VOTER_URL}/api/candidates`).then(x => x.json());
  if (r.status !== 'success' || !r.candidates?.length) throw new Error('無法取得候選人清單');
  return r.candidates;
}

async function runOneVoter(voter, candidates) {
  const candidate = candidates[Math.floor(Math.random() * candidates.length)];
  try {
    const { privateKey, certPem } = await registerVoter(voter.voterId, voter.otp);
    const result = await castVote(voter.voterId, privateKey, certPem, candidate);
    log(`✓ ${voter.voterId} 投給「${candidate}」成功（m_hex=${result.m_hex.slice(0, 16)}...）`);
    appendLog({ voter_id: voter.voterId, candidate, status: 'success', m_hex: result.m_hex, at: new Date().toISOString() });
  } catch (e) {
    log(`✗ ${voter.voterId} 失敗：${e.message}`);
    appendLog({ voter_id: voter.voterId, candidate, status: 'error', message: e.message, at: new Date().toISOString() });
  }
}

// ============================================================
// 主流程
// ============================================================
async function main() {
  if (!existsSync(CONFIG.LOG_FILE)) writeFileSync(CONFIG.LOG_FILE, '');

  log(`=== 選民分時投票模擬開始 ===`);
  log(`目標：${CONFIG.NUM_VOTERS} 人，時間窗 ${CONFIG.ELECTION_WINDOW_SECONDS} 秒`);

  const candidates = await getCandidates();
  log(`候選人清單：${candidates.join('、')}`);

  const voters = await createVoters(CONFIG.NUM_VOTERS);
  const scheduled = assignVoteOffsets(voters, CONFIG.ELECTION_WINDOW_SECONDS, CONFIG.DIST);

  log(`已排定 ${scheduled.length} 位選民的投票時間點，開始等待各自的時間點觸發...`);
  log(`（此腳本會持續執行到最後一位選民投完票為止，過程中可隨時 Ctrl+C 中止）`);

  const startedAt = Date.now();
  const pending = scheduled.map(v => new Promise(resolve => {
    const delayMs = v.offsetSeconds * 1000;
    setTimeout(() => {
      runOneVoter(v, candidates).finally(resolve);
    }, delayMs);
  }));

  // 每 5 分鐘印一次進度摘要
  const progressTimer = setInterval(() => {
    const elapsedMin = ((Date.now() - startedAt) / 60000).toFixed(1);
    log(`（進度回報）已經過 ${elapsedMin} 分鐘...`);
  }, 5 * 60 * 1000);

  await Promise.all(pending);
  clearInterval(progressTimer);

  log(`=== 全部 ${scheduled.length} 位選民已完成排程（含失敗的） ===`);
  log(`詳細結果請查看 ${CONFIG.LOG_FILE}`);
}

main().catch(e => {
  console.error('腳本執行發生未預期的錯誤：', e);
  process.exit(1);
});
