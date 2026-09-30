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
  ADMIN_URL: 'https://localhost:5010',

  // Admin 用的是自簽憑證（不是 Let's Encrypt），Node 預設會拒絕，
  // 這個開關只在呼叫 ADMIN_URL 那幾支請求時暫時關閉憑證驗證。
  ADMIN_SELF_SIGNED: true,

  NUM_VOTERS: 2500,
  VOTER_ID_PREFIX: 'SIM',          // 產生的學號會長這樣：SIM0001, SIM0002...

  // 投票開放時間窗長度（秒），要跟 config.json 的 vote_duration_seconds
  // 一致，否則排到窗口外的投票會在送出時被拒絕（DEADLINE_PASSED）。
  // 啟動時會向 TA 查詢實際剩餘秒數，若比這裡短就改用剩餘秒數（選舉
  // 可能早在腳本啟動前就開始了），查不到才用這個值。
  ELECTION_WINDOW_SECONDS: 86400,
  // 排程時預留給結尾的緩衝（秒），避免最後一批人連同重試都擠到截止之後
  DEADLINE_SAFETY_MARGIN_SECONDS: 600,

  // 失敗自動重試：只重試「單一步驟」而非整個流程——OTP 與 Voting Token
  // 都是一次性的，整個重跑會在註冊那一步就被拒絕。
  // 會重試的情況：網路錯誤／逾時、HTTP 429（限流）、5xx、回應不是 JSON。
  // 不會重試的情況：其他 4xx（截止、OTP 錯誤、Token 已使用等，重試也沒用）。
  // 帶簽章的請求（註冊 PoP、TPA 認證封包）每次重試都會重新產生 timestamp
  // 與 nonce，否則會被伺服器以「時間偏差」「nonce 已使用」拒絕。
  RETRY: {
    BASE_DELAY_MS: 2000,
    MAX_DELAY_MS: 60000,           // 單次等待上限（指數退避 + 隨機抖動）
    MAX_RETRY_MINUTES: 15,         // 單一步驟最多重試多久（仍不會超過截止時間）
    REQUEST_TIMEOUT_MS: 30000,     // 單次請求逾時
  },

  // 同時進行投票流程的選民上限。到了排定時間但名額已滿的選民會排隊等待。
  // 不設上限時，尖峰時段加上重試會讓上千個請求同時打進伺服器（上一輪 2500
  // 人模擬就是這樣把伺服器拖垮的）。所有選民都從同一個 IP 發出，voter_client
  // 的限流（預設每 IP 每分鐘 10 次）本來就只容許約每分鐘 10 人，開再多並發
  // 也只是多製造 429。
  MAX_CONCURRENT_VOTERS: 5,

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

// 截止時間（epoch ms），main() 啟動時設定；重試不會超過這個時間點
let _deadlineAt = Infinity;

/**
 * 全體共用的冷卻時間點（epoch ms）：任何一個請求遇到限流、逾時或 5xx，
 * 所有選民都先暫停到這個時間點再送，避免每個人各自重試、一起猛打伺服器。
 */
let _cooldownUntil = 0;

/**
 * 呼叫 VOTER_URL 並解析 JSON，遇到暫時性失敗自動重試。
 * 回傳解析後的 JSON；非暫時性的 4xx 直接回傳交給呼叫端判斷。
 * makeBody：選填，每次嘗試前呼叫以產生 request body（帶 timestamp/nonce
 * 的簽章請求必須每次重新產生）。
 * ctx.retries 會累加這次多重試了幾次，供日誌統計。
 */
async function fetchJsonWithRetry(ctx, label, path, options = {}, makeBody = null) {
  const R = CONFIG.RETRY;
  const giveUpAt = Math.min(Date.now() + R.MAX_RETRY_MINUTES * 60000, _deadlineAt);
  let lastErr = '';
  for (let attempt = 1; ; attempt++) {
    const wait = _cooldownUntil - Date.now();
    if (wait > 0) await sleep(wait);
    try {
      const body = makeBody ? await makeBody() : options.body;
      const resp = await fetch(CONFIG.VOTER_URL + path, { ...options, body, signal: AbortSignal.timeout(R.REQUEST_TIMEOUT_MS) });
      const text = await resp.text();
      let data;
      try { data = JSON.parse(text); } catch { data = null; }
      if (resp.status === 429 || resp.status >= 500 || data === null) {
        lastErr = `HTTP ${resp.status}${data?.message ? ' ' + data.message : data === null ? '（回應不是 JSON）' : ''}`;
      } else {
        ctx.retries += attempt - 1;
        return data;
      }
    } catch (e) {
      lastErr = e.name === 'TimeoutError' ? `逾時 ${R.REQUEST_TIMEOUT_MS}ms` : e.message;
    }
    const delay = Math.random() * Math.min(R.MAX_DELAY_MS, R.BASE_DELAY_MS * 2 ** (attempt - 1));
    _cooldownUntil = Math.max(_cooldownUntil, Date.now() + delay);
    if (Date.now() + delay >= giveUpAt) {
      ctx.retries += attempt - 1;
      throw new Error(`${label}：重試 ${attempt - 1} 次仍失敗（${lastErr}）`);
    }
    await sleep(delay);
  }
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
      const r = await fetchJsonWithRetry({ retries: 0 }, '取得 CA 根憑證', '/api/proxy/ca/ca_cert');
      if (r.status !== 'success' || !r.ca_certificate) throw new Error('無法取得 CA 根憑證：' + (r.message || ''));
      const { spkiBytes } = vcrypto.parseCertificate(r.ca_certificate);
      return vcrypto.importCaVerifyKey(spkiBytes);
    })();
    // 失敗時清掉快取，讓下一位選民重新取得，而不是所有人永遠拿到同一個失敗結果
    _caPublicKeyPromise.catch(() => { _caPublicKeyPromise = null; });
  }
  return _caPublicKeyPromise;
}

async function registerVoter(ctx, voterId, otp) {
  const keypair = await vcrypto.generateRSAKeypair();
  const pubPEM = await vcrypto.exportPublicKeyPEM(keypair.publicKey);

  // 每次嘗試都重新簽 PoP（timestamp 有效期限 300 秒）
  const data = await fetchJsonWithRetry(ctx, '註冊', '/api/proxy/ca/issue_cert', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
  }, async () => {
    const ts = Math.floor(Date.now() / 1000);
    const popSig = await vcrypto.rsaPssSign(keypair.privateKey, `REGISTER|${voterId}|${ts}`);
    return JSON.stringify({ entity_id: voterId, public_key: pubPEM, otp, timestamp: ts, pop_signature: popSig });
  });
  if (data.status !== 'success') throw new Error('註冊失敗：' + (data.message || data.code || ''));

  return { privateKey: keypair.privateKey, certPem: data.certificate };
}

async function castVote(ctx, voterId, privateKey, certPem, candidate) {
  const [tpaR, ccR, taR] = await Promise.all([
    fetchJsonWithRetry(ctx, '取得 TPA 公鑰', '/api/proxy/tpa/public_key'),
    fetchJsonWithRetry(ctx, '取得 CC 公鑰', '/api/proxy/cc/public_key'),
    fetchJsonWithRetry(ctx, '取得 TA 公鑰', '/api/proxy/ta/public_key'),
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

  // 每次嘗試都重新產生認證封包（nonce 只能用一次、timestamp 有容許誤差）
  const authData = await fetchJsonWithRetry(ctx, 'TPA 認證', '/api/proxy/tpa/auth', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
  }, async () => {
    const authPkt = await vcrypto.createAuthPacket(voterId, 'TPA', privateKey, certPem);
    return JSON.stringify({ auth_packet: authPkt, voter_cert_pem: certPem });
  });
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

  const signData = await fetchJsonWithRetry(ctx, '盲簽章', '/api/proxy/tpa/blind_sign', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ m_prime_hex, voting_token: votingToken }),
  });
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

  // voter_client 以 token_hash 去重，重送同一封信封會回 queued，重試是安全的
  const submitData = await fetchJsonWithRetry(ctx, '信封提交', '/api/submit_envelope', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(envelope),
  });
  if (submitData.status !== 'queued') throw new Error('信封提交失敗：' + (submitData.message || submitData.code || ''));

  return { m_hex, candidate };
}

async function getCandidates() {
  const r = await fetchJsonWithRetry({ retries: 0 }, '取得候選人清單', '/api/candidates');
  if (r.status !== 'success' || !r.candidates?.length) throw new Error('無法取得候選人清單');
  return r.candidates;
}

const _stats = { success: 0, error: 0, retries: 0 };

// 簡單的並發上限：名額滿了就排隊，前一位完成才放下一位進來
let _activeVoters = 0;
const _waitQueue = [];
async function withVoterSlot(fn) {
  if (_activeVoters >= CONFIG.MAX_CONCURRENT_VOTERS) {
    await new Promise(resolve => _waitQueue.push(resolve));
  } else {
    _activeVoters++;
  }
  try {
    return await fn();
  } finally {
    const next = _waitQueue.shift();
    if (next) next();          // 名額直接交給下一位，_activeVoters 不變
    else _activeVoters--;
  }
}

async function runOneVoter(voter, candidates) {
  const candidate = candidates[Math.floor(Math.random() * candidates.length)];
  const ctx = { retries: 0 };
  try {
    const { privateKey, certPem } = await registerVoter(ctx, voter.voterId, voter.otp);
    const result = await castVote(ctx, voter.voterId, privateKey, certPem, candidate);
    _stats.success++;
    log(`✓ ${voter.voterId} 投給「${candidate}」成功（m_hex=${result.m_hex.slice(0, 16)}...，重試 ${ctx.retries} 次）`);
    appendLog({ voter_id: voter.voterId, candidate, status: 'success', m_hex: result.m_hex, retries: ctx.retries, at: new Date().toISOString() });
  } catch (e) {
    _stats.error++;
    log(`✗ ${voter.voterId} 失敗：${e.message}`);
    appendLog({ voter_id: voter.voterId, candidate, status: 'error', message: e.message, retries: ctx.retries, at: new Date().toISOString() });
  } finally {
    _stats.retries += ctx.retries;
  }
}

// ============================================================
// 主流程
// ============================================================
async function main() {
  if (!existsSync(CONFIG.LOG_FILE)) writeFileSync(CONFIG.LOG_FILE, '');

  log(`=== 選民分時投票模擬開始 ===`);

  // 以 TA 回報的實際剩餘秒數為準（選舉可能早在腳本啟動前就開始了）
  let windowSeconds = CONFIG.ELECTION_WINDOW_SECONDS;
  try {
    const d = await fetchJsonWithRetry({ retries: 0 }, '查詢截止時間', '/api/proxy/ta/deadline');
    if (d.election_state === 'running' && typeof d.remaining_seconds === 'number') {
      _deadlineAt = Date.now() + d.remaining_seconds * 1000;
      windowSeconds = Math.min(windowSeconds, d.remaining_seconds);
      log(`TA 回報剩餘 ${d.remaining_seconds} 秒`);
    } else {
      log(`警告：選舉狀態為 ${d.election_state}，沿用設定的時間窗`);
    }
  } catch (e) {
    log(`警告：查不到截止時間（${e.message}），沿用設定的時間窗`);
  }
  windowSeconds = Math.max(windowSeconds - CONFIG.DEADLINE_SAFETY_MARGIN_SECONDS, 60);
  log(`目標：${CONFIG.NUM_VOTERS} 人，排程時間窗 ${windowSeconds} 秒`);

  const candidates = await getCandidates();
  log(`候選人清單：${candidates.join('、')}`);

  const voters = await createVoters(CONFIG.NUM_VOTERS);
  const scheduled = assignVoteOffsets(voters, windowSeconds, CONFIG.DIST);

  log(`已排定 ${scheduled.length} 位選民的投票時間點，開始等待各自的時間點觸發...`);
  log(`（此腳本會持續執行到最後一位選民投完票為止，過程中可隨時 Ctrl+C 中止）`);

  const startedAt = Date.now();
  const pending = scheduled.map(v => new Promise(resolve => {
    const delayMs = v.offsetSeconds * 1000;
    setTimeout(() => {
      withVoterSlot(() => runOneVoter(v, candidates)).finally(resolve);
    }, delayMs);
  }));

  // 每 5 分鐘印一次進度摘要
  const progressTimer = setInterval(() => {
    const elapsedMin = ((Date.now() - startedAt) / 60000).toFixed(1);
    log(`（進度回報）已經過 ${elapsedMin} 分鐘，成功 ${_stats.success}、失敗 ${_stats.error}、累計重試 ${_stats.retries} 次、進行中 ${_activeVoters}、排隊中 ${_waitQueue.length}`);
  }, 5 * 60 * 1000);

  await Promise.all(pending);
  clearInterval(progressTimer);

  log(`=== 全部 ${scheduled.length} 位選民已完成排程（含失敗的） ===`);
  log(`成功 ${_stats.success}、失敗 ${_stats.error}、累計重試 ${_stats.retries} 次`);
  log(`詳細結果請查看 ${CONFIG.LOG_FILE}`);
}

main().catch(e => {
  console.error('腳本執行發生未預期的錯誤：', e);
  process.exit(1);
});
