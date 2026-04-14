const crypto = require('crypto');
const { URL } = require('url');
const fs = require('fs').promises;
const path = require('path');
const os = require('os');

const MERCHANT_ID_DEFAULT = process.env.MERCHANT_ID || '863990030700270';
const CARDZONE_MKREQ_URL = process.env.CARDZONE_MKREQ_URL || 'https://3dsecure.bob.bt/3dss/mkReq';
const CARDZONE_REDIRECT_URL =
  process.env.CARDZONE_REDIRECT_URL ||
  process.env.CARDZONE_MERCREQ_URL ||
  'https://3dsecure.bob.bt/3dss/mercReq';
const CARDZONE_INQUIRY_URL =
  process.env.CARDZONE_INQUIRY_URL ||
  process.env.CARDZONE_MERCREQ_URL ||
  CARDZONE_REDIRECT_URL;
const CARDZONE_REFUND_URL =
  process.env.CARDZONE_REFUND_URL ||
  process.env.CARDZONE_MERCREQ_URL ||
  CARDZONE_INQUIRY_URL;
const CARDZONE_PROFILE_URL = process.env.CARDZONE_PROFILE_URL || '';
const MERCHANT_CURRENCY_DB_PATH =
  process.env.MERCHANT_CURRENCY_DB_PATH || path.join(process.cwd(), 'data', 'merchant-currency.json');
const ENABLE_MKREQ_MAC = process.env.ENABLE_MKREQ_MAC === 'true';
const TEMP_DIR = process.env.VERCEL ? '/tmp' : path.join(os.tmpdir(), 'cardzone-backend');
const PAYMENT_LINK_TTL_MS = Number(process.env.PAYMENT_LINK_TTL_MS || 7 * 24 * 60 * 60 * 1000);
const REFUND_DEFAULT_CURRENCY = process.env.REFUND_DEFAULT_CURRENCY || '840';

const txStore = new Map();

function getRequestBaseUrl(req) {
  if (process.env.CALLBACK_BASE_URL) return process.env.CALLBACK_BASE_URL;
  const fallbackProto = req.socket?.encrypted ? 'https' : 'http';
  const proto = (req.headers['x-forwarded-proto'] || fallbackProto).toString().split(',')[0].trim();
  const host = (req.headers['x-forwarded-host'] || req.headers.host || '').toString().split(',')[0].trim();
  return `${proto}://${host}`;
}

function escapeHtml(s = '') {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => {
      data += chunk;
      if (data.length > 2 * 1024 * 1024) {
        reject(new Error('Request too large'));
        req.destroy();
      }
    });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

function parseForm(body) {
  const params = new URLSearchParams(body);
  const obj = {};
  for (const [k, v] of params.entries()) obj[k] = v;
  return obj;
}

function parseRawPayload(raw, contentType) {
  if (contentType.includes('application/json')) {
    try {
      return JSON.parse(raw || '{}');
    } catch {
      return {};
    }
  }
  return parseForm(raw || '');
}

function json(res, status, payload) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(payload, null, 2));
}

function html(res, status, content) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.end(content);
}

function redirect(res, location) {
  res.statusCode = 302;
  res.setHeader('Location', location);
  res.end();
}

function generateTxnId() {
  const now = new Date();
  const yyyy = now.getFullYear();
  const MM = String(now.getMonth() + 1).padStart(2, '0');
  const dd = String(now.getDate()).padStart(2, '0');
  const hh = String(now.getHours()).padStart(2, '0');
  const mm = String(now.getMinutes()).padStart(2, '0');
  const ss = String(now.getSeconds()).padStart(2, '0');
  const rand = String(Math.floor(Math.random() * 100000)).padStart(5, '0');
  return `${yyyy}${MM}${dd}${hh}${mm}${ss}${rand}`.slice(0, 20);
}

function formatPurchDate(date = new Date()) {
  const yyyy = date.getFullYear();
  const MM = String(date.getMonth() + 1).padStart(2, '0');
  const dd = String(date.getDate()).padStart(2, '0');
  const hh = String(date.getHours()).padStart(2, '0');
  const mm = String(date.getMinutes()).padStart(2, '0');
  const ss = String(date.getSeconds()).padStart(2, '0');
  return `${yyyy}${MM}${dd}${hh}${mm}${ss}`;
}

function amountToMinorUnits(amountText) {
  const n = Number(amountText);
  if (!Number.isFinite(n) || n <= 0) throw new Error('Invalid amount. Amount must be greater than 0.');
  return String(Math.round(n * 100));
}

function base64Url(buf) {
  return Buffer.from(buf)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function createRsaKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const publicDer = crypto.createPublicKey(publicKey).export({ type: 'spki', format: 'der' });
  return {
    publicKeyPem: publicKey,
    privateKeyPem: privateKey,
    publicKeyBase64Url: base64Url(publicDer),
  };
}

function signSha256WithRsaBase64Url(message, privateKeyPem) {
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(message, 'utf8');
  signer.end();
  return base64Url(signer.sign(privateKeyPem));
}

function verifySha256WithRsaBase64Url(message, signatureBase64Url, publicKeyPemOrDerBase64Url) {
  try {
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(message, 'utf8');
    verifier.end();

    let publicKey;
    if (publicKeyPemOrDerBase64Url.includes('BEGIN PUBLIC KEY')) {
      publicKey = publicKeyPemOrDerBase64Url;
    } else {
      const der = Buffer.from(
        publicKeyPemOrDerBase64Url.replace(/-/g, '+').replace(/_/g, '/'),
        'base64'
      );
      publicKey = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' }).export({
        format: 'pem',
        type: 'spki',
      });
    }

    const sig = Buffer.from(signatureBase64Url.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    return verifier.verify(publicKey, sig);
  } catch {
    return false;
  }
}

function mkReqSignString({ merchantId, purchaseId, pubKey }) {
  return `${merchantId || ''}${purchaseId || ''}${pubKey || ''}`;
}

function normalizeCurrency(value) {
  const v = String(value || '').trim();
  return /^\d{3}$/.test(v) ? v : '';
}

function normalizeMerchantId(value) {
  return String(value || '').replace(/\D/g, '');
}

async function loadMerchantCurrencyDb() {
  try {
    const raw = await fs.readFile(MERCHANT_CURRENCY_DB_PATH, 'utf8');
    const parsed = JSON.parse(raw || '{}');
    const map = new Map();

    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      for (const [mid, curr] of Object.entries(parsed)) {
        const id = normalizeMerchantId(mid);
        const code = normalizeCurrency(curr);
        if (id && code) map.set(id, code);
      }
    }

    return map;
  } catch {
    return new Map();
  }
}

function extractCurrencyCandidates(payload) {
  if (!payload || typeof payload !== 'object') return [];

  const keys = [
    'currency', 'currencies', 'currencyCode', 'currencyCodes',
    'defaultCurrency', 'txnCurrency', 'supportedCurrencies', 'allowedCurrencies',
  ];

  const out = new Set();

  for (const k of keys) {
    const raw = payload[k];
    if (Array.isArray(raw)) {
      for (const item of raw) {
        const n = normalizeCurrency(item?.code || item?.currency || item);
        if (n) out.add(n);
      }
      continue;
    }

    if (raw && typeof raw === 'object') {
      const n = normalizeCurrency(raw.code || raw.currency || raw.value);
      if (n) out.add(n);
      continue;
    }

    const n = normalizeCurrency(raw);
    if (n) out.add(n);
  }

  if (payload.data && typeof payload.data === 'object') {
    for (const c of extractCurrencyCandidates(payload.data)) out.add(c);
  }

  return [...out];
}

async function fetchCardzoneMerchantProfile(merchantId) {
  if (!CARDZONE_PROFILE_URL) return null;

  const endpoint = CARDZONE_PROFILE_URL.includes('{merchantId}')
    ? CARDZONE_PROFILE_URL.replace('{merchantId}', encodeURIComponent(merchantId))
    : CARDZONE_PROFILE_URL;

  const r = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ merchantId }),
  });

  const text = await r.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    return null;
  }

  if (!r.ok) return null;
  return data;
}

async function resolveMerchantCurrency(merchantId) {
  const mid = normalizeMerchantId(merchantId);
  if (!mid) return { currency: '', source: 'missing-mid' };

  const db = await loadMerchantCurrencyDb();
  const dbCurrency = db.get(mid);
  if (dbCurrency) {
    return { currency: dbCurrency, source: 'mid-database' };
  }

  try {
    const profile = await fetchCardzoneMerchantProfile(mid);
    const candidates = extractCurrencyCandidates(profile || {});
    if (candidates.length) {
      return { currency: candidates[0], source: 'merchant-profile' };
    }
  } catch {
    // Ignore lookup failures and fail clearly if MID is not configured
  }

  return { currency: '', source: 'not-configured' };
}

function getMpiReqMacFieldSequence(fields) {
  const lineItems = Array.isArray(fields.MPI_LINE_ITEM) ? fields.MPI_LINE_ITEM : [];
  const flattenedLineItems = lineItems
    .map(item => `${item.MPI_ITEM_ID || ''}${item.MPI_ITEM_REMARK || ''}${item.MPI_ITEM_QUANTITY || ''}${item.MPI_ITEM_AMOUNT || ''}${item.MPI_ITEM_CURRENCY || ''}`)
    .join('');

  // NOTE: Phone fields (MPI_HOME_PHONE*, MPI_MOBILE_PHONE*, MPI_WORK_PHONE*) are intentionally 
  // excluded from MAC signing to avoid field concatenation issues. Will be added back 
  // once Cardzone confirms correct field order and null-handling requirements.
  return [
    ['MPI_TRANS_TYPE', fields.MPI_TRANS_TYPE],
    ['MPI_MERC_ID', fields.MPI_MERC_ID],
    ['MPI_PAN', fields.MPI_PAN],
    ['MPI_CARD_HOLDER_NAME', fields.MPI_CARD_HOLDER_NAME],
    ['MPI_PAN_EXP', fields.MPI_PAN_EXP],
    ['MPI_CVV2', fields.MPI_CVV2],
    ['MPI_TRXN_ID', fields.MPI_TRXN_ID],
    ['MPI_ORI_TRXN_ID', fields.MPI_ORI_TRXN_ID],
    ['MPI_PURCH_DATE', fields.MPI_PURCH_DATE],
    ['MPI_PURCH_CURR', fields.MPI_PURCH_CURR],
    ['MPI_PURCH_AMT', fields.MPI_PURCH_AMT],
    ['MPI_ADDR_MATCH', fields.MPI_ADDR_MATCH],
    ['MPI_BILL_ADDR_CITY', fields.MPI_BILL_ADDR_CITY],
    ['MPI_BILL_ADDR_STATE', fields.MPI_BILL_ADDR_STATE],
    ['MPI_BILL_ADDR_CNTRY', fields.MPI_BILL_ADDR_CNTRY],
    ['MPI_BILL_ADDR_POSTCODE', fields.MPI_BILL_ADDR_POSTCODE],
    ['MPI_BILL_ADDR_LINE1', fields.MPI_BILL_ADDR_LINE1],
    ['MPI_BILL_ADDR_LINE2', fields.MPI_BILL_ADDR_LINE2],
    ['MPI_BILL_ADDR_LINE3', fields.MPI_BILL_ADDR_LINE3],
    ['MPI_SHIP_ADDR_CITY', fields.MPI_SHIP_ADDR_CITY],
    ['MPI_SHIP_ADDR_STATE', fields.MPI_SHIP_ADDR_STATE],
    ['MPI_SHIP_ADDR_CNTRY', fields.MPI_SHIP_ADDR_CNTRY],
    ['MPI_SHIP_ADDR_POSTCODE', fields.MPI_SHIP_ADDR_POSTCODE],
    ['MPI_SHIP_ADDR_LINE1', fields.MPI_SHIP_ADDR_LINE1],
    ['MPI_SHIP_ADDR_LINE2', fields.MPI_SHIP_ADDR_LINE2],
    ['MPI_SHIP_ADDR_LINE3', fields.MPI_SHIP_ADDR_LINE3],
    ['MPI_EMAIL', fields.MPI_EMAIL],
    ['MPI_LINE_ITEM_FLATTENED', flattenedLineItems],
    ['MPI_RESPONSE_TYPE', fields.MPI_RESPONSE_TYPE],
  ];
}

function mpiReqSignString(fields) {
  return getMpiReqMacFieldSequence(fields)
    .map(([, value]) => value || '')
    .join('');
}

function buildMpiReqMacDebugRows(fields) {
  return getMpiReqMacFieldSequence(fields).map(([field, value]) => ({
    field,
    value: value || '',
  }));
}

function logMpiReqSigningDetails(fields, preSignString, generatedMac) {
  const sequenceRows = buildMpiReqMacDebugRows(fields);
  console.log('\n========== MPIReq MAC SIGNING DEBUG ==========');
  console.log('[Cardzone][signing] MPIReq payload fields:');
  console.log(JSON.stringify(fields, null, 2));
  console.log('\n[Cardzone][signing] MAC field sequence in exact order (name -> value):');
  sequenceRows.forEach((row, idx) => {
    const val = row.value || '';
    const preview = val.length > 60 ? val.substring(0, 60) + '...' : val;
    console.log(`  [${idx + 1}] ${row.field}: "${preview}"`);
  });
  console.log('\n[Cardzone][signing] Field names in sequence:');
  console.log(sequenceRows.map(item => item.field).join(' -> '));
  console.log('\n[Cardzone][signing] Concatenated pre-sign string:');
  console.log(`"${preSignString}"`);
  console.log(`Pre-sign string length: ${preSignString.length} characters`);
  console.log('\n[Cardzone][signing] Generated MPI_MAC (Base64URL, no padding):');
  console.log(generatedMac);
  console.log('============================================\n');
}

function mpiResVerifyString(fields) {
  return [
    fields.MPI_MERC_ID,
    fields.MPI_TRXN_ID,
    fields.MPI_ERROR_CODE,
    fields.MPI_APPR_CODE,
    fields.MPI_RRN,
    fields.MPI_BIN,
    fields.MPI_REFERRAL_CODE,
    fields.MPI_CARDHOLDER_INFO,
  ].map(v => v || '').join('');
}

const RESPONSE_CODE_DESCRIPTIONS = {
  '0': 'APPROVED',
  '00': 'APPROVED',
  '00_NR': 'APPROVED NO RECEIPT',
  '00_NRR': 'APPROVED NO RECEIPT REQ',
  '1': 'REFER TO CARD ISSUER',
  '2': 'REFER TO CARD ISSUER SPECIAL CONDITION',
  '3': 'INVALID MERCHANT',
  '4': 'PICK UP CARD',
  '5': 'DO NOT HONOUR',
  '6': 'CHECK VALUE ERROR',
  '8': 'SIGNATURE REQUIRED',
  '10': 'APPROVED PARTIAL AMT',
  '11': 'APPROVED VIP',
  '12': 'INVALID TRXN',
  '13': 'INVALID AMT',
  '14': 'INVALID CARD NUMBER',
  '19': 'REENTER TRXN',
  '20': 'AMOUNT_MISSMATCH',
  '22': 'MPS NO CHEQUE ACC',
  '23': 'MPS NO SAVING ACC',
  '24': 'MPS NO CREDIT ACC',
  '25': 'UNABLE TO LOCATE RECORD ON FILE',
  '30': 'FORMAT ERROR',
  '31': 'BANK NOT SUPPORTED BY SWITCH',
  '34': 'FRAUD CARD',
  '39': 'NO CREDIT ACCOUNT',
  '40': 'FUNCTION NOT SUPPORTED BY ISSUER',
  '41': 'LOST CARD',
  '43': 'STOLEN CARD',
  '44': 'BLOCK TERMINATE CLOSE DESTROY CARD',
  '45': 'NEW UNACTIVATED CARD',
  '46': 'CLOSED CARD ACCT',
  '51': 'INSUFFICIENT FUNDS',
  '52': 'NO CURRENT ACCOUNT',
  '53': 'NO SAVING ACCOUNT',
  '54': 'EXPIRED CARD',
  '55': 'INCORRECT PIN',
  '56': 'NO CARD RECORD',
  '57': 'TRXN NOT PERMITTED TO CARD',
  '58': 'TRXN NOT PERMITTED TO TERMINAL',
  '59': 'SUSPECTED FRAUD',
  '5C': 'NOT SUPPORTED BY ISSUER',
  '61': 'EXCEED AMT LMT',
  '62': 'RESTRICTED CARD',
  '63': 'MPS MAC VER ERROR',
  '65': 'EXCEED CNT LMT',
  '68': 'ISSUER TIMEOUT',
  '72': 'UNACTIVATED ACCOUNT',
  '75': 'PIN TRY EXCEEDED',
  '76': 'INVALID PROD CODE',
  '77': 'RECONCILE ERROR OR HOST TEXT IF SENT',
  '78': 'UNACTIVATED/BLOCK CARD',
  '79': 'DECLINED',
  '80': 'BATCH NUMBER NOT FOUND',
  '82': 'NEGATIVE ONLINE CAM/CVV RESULTS',
  '83': 'ISSUER BLOCKED DUE TO SECURITY REASON',
  '84': 'VALIDATE ARQC ERROR',
  '85': 'NOT DECLINED',
  '86': 'CANNOT VERIFY PIN',
  '87': 'PIN REQUIRED',
  '88': 'CRYPTO FAILED',
  '89': 'BAD TERMINAL ID',
  '91': 'ISSUER OR SWITCH IS INOPERATIVE',
  '92': 'ROUTING ERROR',
  '93': 'CARD VIOLATION CANNOT COMPLETE',
  '94': 'DUPLICATE TRXN',
  '95': 'RECONCILE ERROR',
  '96': 'SYSTEM MALFUNCTION',
  '97': 'ACCOUNT CURRENCY ERROR',
  '98': 'CUP ISSUER TIMEOUT',
  '99': 'PIN BLOCK ERROR',
  '9G': 'BLOCKED BY CARDHOLDER',
  'A0': 'MAC VER ERROR',
  'A1': 'VEHICLE AND DRIVER MISMATCH',
  'A2': 'PIN MANDOTORY',
  'A3': 'VELOCITY EXCEEDED',
  'A4': 'ACQUIRER TIMEOUT',
  'A5': 'ACQUIRER LINK DOWN',
  'A6': 'REVERSAL IN PROGRESS',
  'B0': 'CARDLESS RESERVATION NOT FOUND',
  'B1': 'CARDLESS RESERVATION TIMEOUT',
  'B2': 'CARDLESS RESERVATION EXPIRED',
  'B3': 'CARDLESS RESERVATION LIMIT EXCEEDED',
  'B4': 'CARDLESS RESERVATION CANCEL NOT ALLOWED',
  'B5': 'CARDLESS INVALU ONE TIME PIN',
  'B6': 'CARDLESS EXCEEDED PIN TRY',
  'B7': 'MOBILE REGISTRATION INACTIVE',
  'B8': 'MOBILE REGISTRATION DUPLICATE ACTIVE',
  'B9': 'MOBILE REG NOT FOUND',
  'C0': 'DB CONN ERROR',
  'C2': 'INVAULD CHIP CARD DATA',
  'ERR': 'ATM HOST UNKNOWN ERR',
  'ERR_CN': 'ATM NOTE COUNT ERR CN',
  'ERR_CS': 'ATM CASS SETUP ERR CS',
  'ERR_CT': 'ATM CANCEL OR TIMEOUT ERR CT',
  'ERR_DC': 'ATM CURRENCY NOT MATCHED ERR DC',
  'ERR_DE': 'ATM DISPENSE ERR DE',
  'ERR_DF': 'ATM DEVICE FAULT ERR DF',
  'ERR_EI': 'ATM EXCEED SINGLE CASS NOTE ERR EI',
  'ERR_EM': 'ATM EXCEED MAX NOTE ERR EM',
  'ERR_H': 'ATM HOST ERR H',
  'ERR_IA': 'ATM INVALID AMT ERR IA',
  'ERR_IB': 'ATM INVALID BILLER ID',
  'ERR_IN': 'ATM INVALID NOTE ID ERR IN',
  'ERR_MA': 'ATM MAX AMT ERR MA',
  'ERR_MI': 'ATM MIN AMT ERR MI',
  'ERR_TO': 'ATM HOST TIMEOUT ERR TO',
  'FP': 'FIRST PAGE',
  'FP_NR': 'FIRST PAGE NO RECEIPT',
  'G1': 'GIFT OUT OF STOCK',
  'G2': 'INVALID GIFT',
  'LP': 'LAST PAGE',
  'LP_NR': 'LAST PAGE NO RECEIPT',
  'M0': 'EXCEED MERCHANT DAILY TOPUP LMT',
  'M1': 'TOPUP BELOW MINIMUM LMT',
  'M2': 'TOPUP ABOVE MAXIMUM LMT',
  'MP': 'MIDDLE PAGE',
  'MP_NR': 'MIDDLE PAGE NO RECEIPT',
  'N7': 'INVALID CVV2',
  'NR': 'NO RECEIPT',
  'P0': 'FORCE PIN CHANGE',
  'P1': 'PIN CREATE NOT ALLOWED',
  'R0': 'CASH RETRACT',
  'RR': 'REQUEST REVERSAL',
  'S1': 'NO STANDIN TRXN',
  'S2': 'STANDIN IN PROGRESS',
  'S3': 'NO MORESOFTPIN AVAILABLE',
  'S4': 'NO PACKAGE AVAILABLE',
  'S5': 'NO SOFTPIN PACKAGES FOUND',
};

function getResponseReasonFromCode(responseCode, fallbackReason = '') {
  const code = String(responseCode || '').trim().toUpperCase();
  if (!code) return String(fallbackReason || '').trim();

  if (RESPONSE_CODE_DESCRIPTIONS[code]) {
    return RESPONSE_CODE_DESCRIPTIONS[code];
  }

  if (/^0+$/.test(code)) {
    return RESPONSE_CODE_DESCRIPTIONS['00'] || RESPONSE_CODE_DESCRIPTIONS['0'] || String(fallbackReason || '').trim();
  }

  if (/^\d+$/.test(code)) {
    const normalizedNumericCode = String(Number.parseInt(code, 10));
    if (RESPONSE_CODE_DESCRIPTIONS[normalizedNumericCode]) {
      return RESPONSE_CODE_DESCRIPTIONS[normalizedNumericCode];
    }
  }

  return String(fallbackReason || '').trim();
}

function extractFinalResultFields(fields = {}) {
  return {
    authorizationCode: String(fields.MPI_APPR_CODE || '').trim(),
    referenceNumber: String(fields.MPI_RRN || '').trim(),
    responseCode: String(fields.MPI_ERROR_CODE || '').trim(),
    responseReason: String(fields.MPI_ERROR_DESC || fields.MPI_CARDHOLDER_INFO || '').trim(),
    referralCode: String(fields.MPI_REFERRAL_CODE || '').trim(),
    bin: String(fields.MPI_BIN || '').trim(),
  };
}

function hasSufficientFinalResult(finalResult) {
  if (!finalResult) return false;
  return !!(
    finalResult.responseCode ||
    finalResult.authorizationCode ||
    finalResult.referenceNumber ||
    finalResult.responseReason
  );
}

function buildFinalResultRecord({ fields, source, resolvedAt }) {
  if (!fields || typeof fields !== 'object') return null;

  const extracted = extractFinalResultFields(fields);
  if (!Object.values(extracted).some(Boolean)) return null;

  return {
    source,
    resolvedAt: resolvedAt || new Date().toISOString(),
    ...extracted,
  };
}

function mapFinalPaymentStatus(finalResult) {
  if (!hasSufficientFinalResult(finalResult)) return 'PENDING';
  if (finalResult.responseCode === '000' && finalResult.authorizationCode) return 'SUCCESS';
  return 'FAILED';
}

function mapTransactionLifecycleStatus({ callbackReceived, finalResult }) {
  if (!callbackReceived && !finalResult) return 'PENDING';
  return mapFinalPaymentStatus(finalResult);
}

function txFilePath(txnId) {
  const safeId = String(txnId || '').replace(/[^a-zA-Z0-9_-]/g, '');
  return path.join(TEMP_DIR, `txn_${safeId}.json`);
}

function paymentLinkFilePath(token) {
  const safeToken = String(token || '').replace(/[^a-zA-Z0-9_-]/g, '');
  return path.join(TEMP_DIR, `paylink_${safeToken}.json`);
}

async function saveTransaction(tx) {
  txStore.set(tx.txnId, tx);
  await fs.mkdir(TEMP_DIR, { recursive: true });
  await fs.writeFile(txFilePath(tx.txnId), JSON.stringify(tx, null, 2), 'utf8');
}

async function getTransaction(txnId) {
  const id = String(txnId || '').trim();
  if (!id) return null;

  const inMemory = txStore.get(id);
  if (inMemory) return inMemory;

  try {
    const content = await fs.readFile(txFilePath(id), 'utf8');
    const tx = JSON.parse(content);
    txStore.set(id, tx);
    return tx;
  } catch {
    return null;
  }
}

async function savePaymentLink(link) {
  await fs.mkdir(TEMP_DIR, { recursive: true });
  await fs.writeFile(paymentLinkFilePath(link.token), JSON.stringify(link, null, 2), 'utf8');
}

async function getPaymentLink(token) {
  const id = String(token || '').trim();
  if (!id) return null;

  try {
    const content = await fs.readFile(paymentLinkFilePath(id), 'utf8');
    return JSON.parse(content);
  } catch {
    return null;
  }
}

function matchesTxnReference(tx, referenceId) {
  const ref = String(referenceId || '').trim();
  if (!ref || !tx || typeof tx !== 'object') return false;

  const callbackFields = tx.callback?.fields || {};
  const candidates = [
    tx.txnId,
    callbackFields.MPI_TRXN_ID,
    callbackFields.MPI_ORI_TRXN_ID,
    callbackFields.trxnId,
    callbackFields.txnId,
  ].map(v => String(v || '').trim()).filter(Boolean);

  return candidates.includes(ref);
}

async function findStoredTransactionForRefund(merchantId, originalTxnId) {
  const mid = String(merchantId || '').trim();
  const ref = String(originalTxnId || '').trim();
  if (!mid || !ref) return null;

  const direct = await getTransaction(ref);
  if (direct && String(direct.merchantId || '').trim() === mid) {
    return direct;
  }

  for (const tx of txStore.values()) {
    if (String(tx?.merchantId || '').trim() !== mid) continue;
    if (matchesTxnReference(tx, ref)) return tx;
  }

  try {
    const files = await fs.readdir(TEMP_DIR);
    const txFiles = files.filter(name => /^txn_.+\.json$/i.test(name));

    for (const fileName of txFiles) {
      try {
        const content = await fs.readFile(path.join(TEMP_DIR, fileName), 'utf8');
        const tx = JSON.parse(content);
        if (String(tx?.merchantId || '').trim() !== mid) continue;
        if (!matchesTxnReference(tx, ref)) continue;

        if (tx?.txnId) {
          txStore.set(String(tx.txnId), tx);
        }
        return tx;
      } catch {
        // ignore unreadable transaction files
      }
    }
  } catch {
    // ignore temp directory read errors
  }

  return null;
}

function generatePaymentLinkToken() {
  return crypto.randomBytes(18).toString('base64url');
}

async function doMkReq({ merchantId, purchaseId, merchantPublicKeyBase64Url, merchantPrivateKeyPem }) {
  const payload = {
    merchantId,
    purchaseId,
    pubKey: merchantPublicKeyBase64Url,
  };

  if (ENABLE_MKREQ_MAC) {
    payload.mac = signSha256WithRsaBase64Url(mkReqSignString(payload), merchantPrivateKeyPem);
  } else {
    console.log('[Cardzone][mkReq] mac omitted unless explicitly enabled by Cardzone.');
  }

  console.log('[Cardzone][mkReq] method=POST contentType=application/json endpoint=', CARDZONE_MKREQ_URL);
  const r = await fetch(CARDZONE_MKREQ_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  const text = await r.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error(`mkReq did not return JSON. HTTP ${r.status}. Body: ${text.slice(0, 500)}`);
  }

  if (!r.ok) {
    throw new Error(`mkReq failed. HTTP ${r.status}. Body: ${JSON.stringify(data)}`);
  }

  return { requestPayload: payload, responsePayload: data };
}

function parseCardzoneResponseBody(rawText, contentType = '') {
  const text = String(rawText || '');
  const type = String(contentType || '').toLowerCase();

  if (!text.trim()) return {};

  if (type.includes('application/json') || text.trim().startsWith('{') || text.trim().startsWith('[')) {
    try {
      return JSON.parse(text);
    } catch {
      return {};
    }
  }

  if (type.includes('application/x-www-form-urlencoded') || type.includes('text/plain') || text.includes('=')) {
    return parseForm(text);
  }

  return {};
}

async function doInquiry(tx, originalTxnId) {
  const requestFields = {
    MPI_TRANS_TYPE: 'INQ',
    MPI_MERC_ID: tx.merchantId,
    MPI_ORI_TRXN_ID: originalTxnId,
  };

  const signInput = mpiReqSignString(requestFields);
  requestFields.MPI_MAC = signSha256WithRsaBase64Url(signInput, tx.security.merchantPrivateKeyPem);

  console.log('[Cardzone][inquiry] endpoint=', CARDZONE_INQUIRY_URL);
  console.log('[Cardzone][inquiry] txnId=', originalTxnId);

  const response = await fetch(CARDZONE_INQUIRY_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json, application/x-www-form-urlencoded, text/plain',
    },
    body: new URLSearchParams(requestFields).toString(),
  });

  const rawBody = await response.text();
  const responseFields = parseCardzoneResponseBody(rawBody, response.headers.get('content-type') || '');

  if (!response.ok) {
    throw new Error(`Inquiry failed. HTTP ${response.status}. Body: ${rawBody.slice(0, 500)}`);
  }

  const hasMac = !!responseFields.MPI_MAC;
  const verifyInput = hasMac ? mpiResVerifyString(responseFields) : '';
  const macVerified =
    hasMac && !!tx.security?.cardzonePublicKeyBase64Url
      ? verifySha256WithRsaBase64Url(verifyInput, responseFields.MPI_MAC, tx.security.cardzonePublicKeyBase64Url)
      : false;

  return {
    requestedAt: new Date().toISOString(),
    endpoint: CARDZONE_INQUIRY_URL,
    requestFields,
    signInput,
    responseStatus: response.status,
    responseContentType: response.headers.get('content-type') || '',
    responseFields,
    rawBody,
    macVerification: {
      hasMac,
      macVerified,
      verifyInput,
      verifyNote: hasMac
        ? (macVerified ? 'Inquiry MPIRes MAC verified successfully' : 'Inquiry MPIRes MAC verification failed')
        : 'No MPI_MAC received on inquiry response',
    },
  };
}

function isApprovedResponseCode(responseCode) {
  const code = String(responseCode || '').trim().toUpperCase();
  return code === '000' || code === '00' || code === '0';
}

function pickField(fields, candidates = []) {
  if (!fields || typeof fields !== 'object') return '';

  const candidateList = candidates.map(item => String(item || '').trim()).filter(Boolean);
  const lowerCandidates = new Set(candidateList.map(item => item.toLowerCase()));

  for (const field of candidateList) {
    const value = String(fields?.[field] || '').trim();
    if (value) return value;
  }

  for (const [key, value] of Object.entries(fields)) {
    if (lowerCandidates.has(String(key || '').toLowerCase())) {
      const text = String(value || '').trim();
      if (text) return text;
    }
  }

  const stack = [fields];
  const visited = new Set();
  while (stack.length) {
    const node = stack.pop();
    if (!node || typeof node !== 'object' || visited.has(node)) continue;
    visited.add(node);

    if (Array.isArray(node)) {
      for (const item of node) {
        if (item && typeof item === 'object') stack.push(item);
      }
      continue;
    }

    for (const [key, value] of Object.entries(node)) {
      if (lowerCandidates.has(String(key || '').toLowerCase())) {
        const text = String(value || '').trim();
        if (text) return text;
      }
      if (value && typeof value === 'object') {
        stack.push(value);
      }
    }
  }

  return '';
}

function toMinorUnitsFromGatewayAmount(value) {
  const text = String(value || '').trim();
  if (!text) return 0;
  if (!/^\d+$/.test(text)) return 0;
  return Number.parseInt(text, 10);
}

function mapGatewayStatus(fields = {}) {
  const responseCode = pickField(fields, ['MPI_ERROR_CODE', 'responseCode', 'errorCode']);
  const approvalCode = pickField(fields, ['MPI_APPR_CODE', 'approvalCode']);
  if (isApprovedResponseCode(responseCode) && approvalCode) return 'SUCCESS';
  if (isApprovedResponseCode(responseCode)) return 'APPROVED';
  if (responseCode) return 'FAILED';
  return 'UNKNOWN';
}

function mapGatewayLookupPayload(fields = {}, fallbackTxnId = '') {
  const responseCode = pickField(fields, ['MPI_ERROR_CODE', 'responseCode', 'errorCode']);
  const fallbackReason = pickField(fields, ['MPI_ERROR_DESC', 'MPI_CARDHOLDER_INFO', 'responseReason', 'errorDescription', 'message']);
  const responseReason = getResponseReasonFromCode(responseCode, fallbackReason);

  return {
    txnId: pickField(fields, ['MPI_ORI_TRXN_ID', 'MPI_TRXN_ID', 'txnId', 'trxnId', 'ORI_TRXN_ID']) || fallbackTxnId,
    amount: pickField(fields, ['MPI_PURCH_AMT', 'MPI_TXN_AMT', 'purchAmt', 'txnAmt', 'amount']),
    currency: pickField(fields, ['MPI_PURCH_CURR', 'MPI_TXN_CURR', 'purchCurr', 'txnCurr', 'currency']),
    approvalCode: pickField(fields, ['MPI_APPR_CODE', 'approvalCode', 'apprCode']),
    rrn: pickField(fields, ['MPI_RRN', 'rrn']),
    responseCode,
    responseReason,
    status: mapGatewayStatus(fields),
    maskedPan: pickField(fields, ['MPI_PAN', 'maskedPan']),
  };
}

function hasRefundLookupDetails(summary = {}) {
  return !!(
    String(summary.amount || '').trim() ||
    String(summary.currency || '').trim() ||
    String(summary.approvalCode || '').trim() ||
    String(summary.rrn || '').trim() ||
    String(summary.responseCode || '').trim() ||
    String(summary.responseReason || '').trim()
  );
}

function mapStoredTransactionToRefundLookup(tx, originalTxnId) {
  const callbackFields = tx?.callback?.fields || {};
  const final = tx?.finalResult || extractFinalResultFields(callbackFields);
  const responseCode = String(final?.responseCode || '').trim();
  const responseReason = getResponseReasonFromCode(responseCode, String(final?.responseReason || '').trim());
  const fallbackAmount = pickField(callbackFields, ['MPI_PURCH_AMT', 'MPI_TXN_AMT', 'amount']);
  const fallbackCurrency = pickField(callbackFields, ['MPI_PURCH_CURR', 'MPI_TXN_CURR', 'currency']);
  const fallbackTxnId = pickField(callbackFields, ['MPI_TRXN_ID', 'MPI_ORI_TRXN_ID', 'txnId', 'trxnId']);
  const fallbackPan = pickField(callbackFields, ['MPI_PAN', 'maskedPan']);

  return {
    txnId: String(tx?.txnId || fallbackTxnId || originalTxnId || '').trim(),
    amount: String(tx?.amountMinor || fallbackAmount || '').trim(),
    currency: String(tx?.currency || fallbackCurrency || '').trim(),
    approvalCode: String(final?.authorizationCode || '').trim(),
    rrn: String(final?.referenceNumber || '').trim(),
    responseCode,
    responseReason,
    status: String(tx?.status || '').trim() || mapGatewayStatus(callbackFields),
    maskedPan: String(fallbackPan || '').trim(),
    callbackRawFields: callbackFields,
  };
}

async function createCardzoneSession(merchantId, purchaseId) {
  const keys = createRsaKeyPair();
  const mkReq = await doMkReq({
    merchantId,
    purchaseId,
    merchantPublicKeyBase64Url: keys.publicKeyBase64Url,
    merchantPrivateKeyPem: keys.privateKeyPem,
  });

  const mkReqRes = mkReq.responsePayload;
  if (String(mkReqRes.errorCode || '').trim() !== '000' || !mkReqRes.pubKey) {
    throw new Error('mkReq failed for Cardzone session initialization.');
  }

  return {
    keys,
    mkReq,
    cardzonePublicKeyBase64Url: mkReqRes.pubKey,
  };
}

async function postCardzoneNon3dsRequest({ endpoint, requestFields }) {
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json, application/x-www-form-urlencoded, text/plain',
    },
    body: new URLSearchParams(requestFields).toString(),
  });

  const rawBody = await response.text();
  const responseFields = parseCardzoneResponseBody(rawBody, response.headers.get('content-type') || '');

  if (!response.ok) {
    throw new Error(`Cardzone request failed. HTTP ${response.status}. Body: ${rawBody.slice(0, 500)}`);
  }

  return {
    responseStatus: response.status,
    responseContentType: response.headers.get('content-type') || '',
    responseFields,
    rawBody,
  };
}

async function lookupTransactionForRefund({ merchantId, originalTxnId, terminalId }) {
  const purchaseId = generateTxnId();
  const session = await createCardzoneSession(merchantId, purchaseId);

  const requestFields = {
    MPI_TRANS_TYPE: 'INQ',
    MPI_MERC_ID: merchantId,
    MPI_ORI_TRXN_ID: originalTxnId,
  };

  if (terminalId) requestFields.MPI_TERMINAL_ID = terminalId;

  const signInput = mpiReqSignString(requestFields);
  requestFields.MPI_MAC = signSha256WithRsaBase64Url(signInput, session.keys.privateKeyPem);

  const response = await postCardzoneNon3dsRequest({
    endpoint: CARDZONE_INQUIRY_URL,
    requestFields,
  });

  const hasMac = !!response.responseFields.MPI_MAC;
  const verifyInput = hasMac ? mpiResVerifyString(response.responseFields) : '';
  const macVerified =
    hasMac && !!session.cardzonePublicKeyBase64Url
      ? verifySha256WithRsaBase64Url(verifyInput, response.responseFields.MPI_MAC, session.cardzonePublicKeyBase64Url)
      : false;

  let summary = mapGatewayLookupPayload(response.responseFields, originalTxnId);
  if (!hasRefundLookupDetails(summary)) {
    const localTx = await findStoredTransactionForRefund(merchantId, originalTxnId);
    if (localTx && String(localTx.merchantId || '').trim() === String(merchantId || '').trim()) {
      summary = mapStoredTransactionToRefundLookup(localTx, originalTxnId);
    }
  }

  return {
    requestedAt: new Date().toISOString(),
    endpoint: CARDZONE_INQUIRY_URL,
    requestFields,
    signInput,
    responseStatus: response.responseStatus,
    responseContentType: response.responseContentType,
    responseFields: response.responseFields,
    rawBody: response.rawBody,
    macVerification: {
      hasMac,
      macVerified,
      verifyInput,
      verifyNote: hasMac
        ? (macVerified ? 'Inquiry MPIRes MAC verified successfully' : 'Inquiry MPIRes MAC verification failed')
        : 'No MPI_MAC received on inquiry response',
    },
    summary,
  };
}

async function initiateRefundRequest({ merchantId, originalTxnId, refundAmountMinor }) {
  const purchaseId = generateTxnId();
  const session = await createCardzoneSession(merchantId, purchaseId);
  const refundTxnId = generateTxnId();

  const requestFields = {
    MPI_TRANS_TYPE: 'REFUND',
    MPI_MERC_ID: merchantId,
    MPI_ORI_TRXN_ID: originalTxnId,
    MPI_PURCH_CURR: REFUND_DEFAULT_CURRENCY,
    MPI_PURCH_AMT: String(refundAmountMinor),
    MPI_TRXN_ID: refundTxnId,
    MPI_PURCH_DATE: formatPurchDate(new Date()),
  };

  const signInput = mpiReqSignString(requestFields);
  requestFields.MPI_MAC = signSha256WithRsaBase64Url(signInput, session.keys.privateKeyPem);

  const response = await postCardzoneNon3dsRequest({
    endpoint: CARDZONE_REFUND_URL,
    requestFields,
  });

  const responseCode = pickField(response.responseFields, ['MPI_ERROR_CODE', 'responseCode', 'errorCode']);
  const fallbackReason = pickField(response.responseFields, ['MPI_ERROR_DESC', 'MPI_CARDHOLDER_INFO', 'responseReason']);

  return {
    requestedAt: new Date().toISOString(),
    endpoint: CARDZONE_REFUND_URL,
    requestFields,
    signInput,
    responseStatus: response.responseStatus,
    responseContentType: response.responseContentType,
    responseFields: response.responseFields,
    rawBody: response.rawBody,
    result: {
      status: mapGatewayStatus(response.responseFields),
      responseCode,
      responseReason: getResponseReasonFromCode(responseCode, fallbackReason),
      approvalCode: pickField(response.responseFields, ['MPI_APPR_CODE', 'approvalCode']),
      rrn: pickField(response.responseFields, ['MPI_RRN', 'rrn']),
    },
  };
}

function renderAutoPostPage(action, fields) {
  const inputs = Object.entries(fields)
    .filter(([, v]) => v !== undefined && v !== null && v !== '')
    .map(([k, v]) => `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}">`)
    .join('\n');

  return `<!doctype html>
<html>
<head><meta charset="utf-8"><title>Redirecting...</title></head>
<body onload="document.forms[0].submit()" style="font-family:Arial,sans-serif;padding:24px">
  <p>Redirecting to secure Cardzone payment page...</p>
  <form id="payForm" method="post" action="${escapeHtml(action)}">${inputs}</form>
  <noscript><button type="submit" form="payForm">Continue</button></noscript>
  <script>document.forms[0].submit();</script>
</body>
</html>`;
}

function renderMessagePage(title, message, details) {
  const detailBlock = details
    ? `<pre style="background:#111827;color:#e5e7eb;padding:14px;border-radius:10px;overflow:auto">${escapeHtml(JSON.stringify(details, null, 2))}</pre>`
    : '';

  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(title)}</title>
  <style>
    body{font-family:Arial,sans-serif;background:#f5f7fb;padding:24px;color:#111827}
    .card{max-width:900px;margin:0 auto;background:#fff;padding:24px;border-radius:16px;box-shadow:0 10px 30px rgba(0,0,0,.08)}
  </style>
</head>
<body>
  <div class="card">
    <h1>${escapeHtml(title)}</h1>
    <p>${escapeHtml(message)}</p>
    ${detailBlock}
  </div>
</body>
</html>`;
}

function renderResultPage(tx, paymentStatus, finalResult) {
  const statusTone = paymentStatus === 'SUCCESS' ? '#0f9b63' : paymentStatus === 'FAILED' ? '#c62828' : '#c27a00';
  const responseCode = finalResult?.responseCode || '';
  const responseReason = getResponseReasonFromCode(responseCode, finalResult?.responseReason || '');

  const rows = [
    ['Payment status', paymentStatus],
    ['Reference number (RRN)', finalResult?.referenceNumber || '—'],
    ['Authorization code', finalResult?.authorizationCode || '—'],
    ['Response code', responseCode || '—'],
    ['Response reason', responseReason || '—'],
  ].map(([label, value]) => `
      <div class="row">
        <div class="label">${escapeHtml(label)}</div>
        <div class="value">${escapeHtml(value)}</div>
      </div>`).join('');

  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Payment Result</title>
  <style>
    body{font-family:Arial,sans-serif;background:linear-gradient(180deg,#f8fbff 0%,#eef3fb 100%);padding:24px;color:#111827}
    .card{max-width:760px;margin:0 auto;background:#fff;padding:26px;border-radius:18px;box-shadow:0 18px 40px rgba(15,23,42,.10);border:1px solid #e7edf8}
    .badge{display:inline-block;padding:8px 12px;border-radius:999px;font-weight:700;color:#fff;background:${statusTone};margin-bottom:14px}
    h1{margin:0 0 8px;font-size:30px}
    .meta{color:#5f6f86;font-size:14px;margin:0 0 18px}
    .grid{display:grid;gap:12px}
    .row{display:flex;justify-content:space-between;gap:16px;padding:14px 16px;border:1px solid #e5e7eb;border-radius:12px;background:#fafcff}
    .label{font-weight:600;color:#334155}
    .value{text-align:right;word-break:break-word}
    .actions{margin-top:18px;display:flex;justify-content:flex-end}
    .home-btn{display:inline-flex;align-items:center;justify-content:center;padding:11px 16px;border-radius:10px;background:#165dff;color:#fff;text-decoration:none;font-weight:600;box-shadow:0 6px 14px rgba(22,93,255,.25)}
    .home-btn:hover{background:#0f4ed8}
    @media (max-width:640px){.row{flex-direction:column}.value{text-align:left}}
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">${escapeHtml(paymentStatus)}</div>
    <h1>Payment Result</h1>
    <p class="meta">Transaction ID: ${escapeHtml(tx.txnId)}${tx.orderRef ? ` • Order Ref: ${escapeHtml(tx.orderRef)}` : ''}</p>
    <div class="grid">${rows}
    </div>
    <div class="actions">
      <a class="home-btn" href="https://standalone-ip-gintegration.vercel.app/">Back to Home</a>
    </div>
  </div>
</body>
</html>`;
}

function renderDeveloperHome(baseUrl) {
  return `<!doctype html>
<html>
<head><meta charset="utf-8"><title>Cardzone Payment Backend</title></head>
<body style="font-family:Arial,sans-serif;padding:24px">
  <h1>Cardzone payment backend is running</h1>
  <p>This deployment is backend-only. Customer checkout UI must be hosted on merchant website.</p>
  <ul>
    <li>POST ${escapeHtml(baseUrl)}/api/initiate</li>
    <li>POST ${escapeHtml(baseUrl)}/api/refund/lookup</li>
    <li>POST ${escapeHtml(baseUrl)}/api/refund/initiate</li>
    <li>POST ${escapeHtml(baseUrl)}/callback</li>
    <li>GET/POST ${escapeHtml(baseUrl)}/return</li>
    <li>GET ${escapeHtml(baseUrl)}/health</li>
  </ul>
</body>
</html>`;
}

function renderPublicCheckoutPage(baseUrl) {
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Business Payment Portal</title>
  <style>
    :root{
      --bg:#f4f7fb;
      --card:#ffffff;
      --text:#10213a;
      --muted:#5f6f86;
      --brand:#165dff;
      --brand-2:#0e4bd4;
      --border:#dce5f2;
      --ok:#0f9b63;
    }
    *{box-sizing:border-box}
    body{
      margin:0;
      font-family:Inter,Segoe UI,Arial,sans-serif;
      color:var(--text);
      background:linear-gradient(180deg,#f8fbff 0%, var(--bg) 100%);
      min-height:100vh;
      display:flex;
      align-items:center;
      justify-content:center;
      padding:24px 14px;
    }
    .container{width:100%;max-width:680px}
    .card{
      background:var(--card);
      border:1px solid var(--border);
      border-radius:18px;
      box-shadow:0 16px 40px rgba(16,33,58,.10);
      padding:24px 22px;
    }
    .heading{margin-bottom:16px}
    .title{margin:0 0 6px;font-size:26px;line-height:1.2}
    .subtitle{margin:0;color:var(--muted);font-size:14px}
    .tabs{display:flex;gap:8px;margin:14px 0 8px}
    .tab-btn{flex:1;border:1px solid var(--border);background:#f8fbff;color:#243a5e;border-radius:10px;padding:10px 12px;cursor:pointer;font-weight:600}
    .tab-btn.active{background:linear-gradient(180deg,var(--brand),var(--brand-2));border-color:var(--brand-2);color:#fff}
    .panel{display:none}
    .panel.active{display:block}
    .form-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:12px}
    .field{display:flex;flex-direction:column;gap:6px}
    .field.full{grid-column:1 / -1}
    label{font-size:13px;color:#2c3f5f;font-weight:600}
    input,textarea{
      width:100%;
      border:1px solid #cfdced;
      background:#fff;
      color:#10213a;
      border-radius:10px;
      padding:12px 12px;
      outline:none;
      transition:border-color .2s,box-shadow .2s;
      font-size:14px;
    }
    textarea{resize:vertical;min-height:92px}
    input:focus,textarea:focus{border-color:var(--brand);box-shadow:0 0 0 3px rgba(22,93,255,.12)}
    .section-label{
      grid-column:1 / -1;
      margin-top:4px;
      font-size:12px;
      font-weight:700;
      color:#4b5f80;
      text-transform:uppercase;
      letter-spacing:.4px;
    }
    .submit{
      margin-top:18px;
      width:100%;
      background:linear-gradient(180deg,var(--brand),var(--brand-2));
      color:white;
      border:0;
      border-radius:10px;
      padding:13px 16px;
      font-weight:600;
      cursor:pointer;
    }
    .secondary{
      margin-top:12px;
      width:100%;
      background:#f0f4f9;
      color:var(--text);
      border:1px solid var(--border);
      border-radius:10px;
      padding:11px 16px;
      font-weight:500;
      cursor:pointer;
      font-size:14px;
    }
    .secondary:hover{background:#e8ecf4}
    .link-panel{display:none}
    .link-panel.active{display:block}
    .link-panel h3{margin:16px 0 8px;font-size:16px}
    .link-panel p{margin:6px 0;color:var(--muted);font-size:13px}
    .link-output{display:flex;gap:8px;margin:10px 0}
    .link-output input{flex:1;font-size:12px;padding:10px}
    .link-output button{flex:0 0 auto;width:auto;margin-top:0}
    .tiny{font-size:12px;color:#8a9aad}
    .trust{
      margin-top:16px;
      padding:12px;
      border:1px solid #dde8f6;
      border-radius:10px;
      background:#f8fbff;
    }
    .trust ul{margin:0;padding:0;list-style:none;display:grid;gap:8px}
    .trust li{display:flex;align-items:center;gap:8px;color:#3c4f6e;font-size:13px}
    .dot{height:8px;width:8px;border-radius:999px;background:var(--ok);flex:none}
    .result-box{margin-top:12px;padding:12px;border-radius:10px;border:1px solid #dae4f3;background:#f8fbff}
    .result-box h3{margin:0 0 8px;font-size:15px}
    .result-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px 14px}
    .result-item{font-size:13px}
    .result-item strong{display:block;color:#4b5f80;font-size:12px;margin-bottom:2px}
    .status-note{margin-top:10px;font-size:13px;color:#2c3f5f}
    @media (max-width:900px){
      .form-grid{grid-template-columns:1fr}
      .result-grid{grid-template-columns:1fr}
    }
  </style>
</head>
<body>
  <div class="container">
    <section class="card">
      <div class="heading">
        <h1 class="title">Business Payment Portal</h1>
        <p class="subtitle">A standalone payment page for registered merchants to securely collect customer payments.</p>
      </div>

      <div class="tabs">
        <button class="tab-btn active" id="tabPayment" type="button">Make Payment</button>
        <button class="tab-btn" id="tabRefund" type="button">Refund</button>
      </div>

      <section class="panel active" id="panelPayment">

      <form id="checkoutForm" method="post" action="/api/initiate" autocomplete="on">
        <div class="form-grid">
          <div class="section-label">Payment Details</div>

          <div class="field">
            <label for="merchantId">Merchant ID</label>
            <input id="merchantId" name="merchantId" required placeholder="Enter registered MID" />
          </div>

          <div class="field" style="position:relative">
            <label for="amount"><span id="currencyLabel" style="font-weight:600"></span> Amount</label>
            <input id="amount" name="amount" type="number" required min="0.01" step="0.01" placeholder="0.00" />
          </div>

          <div class="section-label">Customer Details</div>

          <div class="field">
            <label for="customerName">Customer Name</label>
            <input id="customerName" name="customerName" placeholder="Enter customer full name" />
          </div>

          <div class="field">
            <label for="email">Customer Email</label>
            <input id="email" name="email" type="email" placeholder="Enter customer email" />
          </div>

          <div class="field full">
            <label for="paymentDescription">Payment Description</label>
            <textarea id="paymentDescription" name="paymentDescription" placeholder="Describe service or purpose of payment"></textarea>
          </div>
        </div>

        <input id="currency" name="currency" type="hidden" value="" />

        <button class="submit" type="submit">Proceed to Secure Payment</button>
        <button class="secondary" type="button" id="generateLinkButton">Generate Payment Link</button>

        <div class="link-panel" id="paymentLinkPanel">
          <h3>Shareable payment link</h3>
          <p>Send this link to the cardholder. Opening it will start the secure Cardzone payment flow.</p>
          <div class="link-output">
            <input id="paymentLinkOutput" readonly value="" />
            <button class="secondary" type="button" id="copyLinkButton">Copy Link</button>
          </div>
          <p class="tiny" id="paymentLinkMeta"></p>
        </div>
      </form>
      </section>

      <section class="panel" id="panelRefund">
        <div class="form-grid">
          <div class="section-label">Refund Lookup</div>

          <div class="field">
            <label for="refundMerchantId">Merchant ID</label>
            <input id="refundMerchantId" placeholder="Enter registered MID" />
          </div>

          <div class="field">
            <label for="refundOriginalTxnId">Original Transaction ID</label>
            <input id="refundOriginalTxnId" placeholder="Enter original txn id" />
          </div>

          <div class="field full">
            <label for="refundTerminalId">Virtual Terminal ID (optional)</label>
            <input id="refundTerminalId" placeholder="Enter virtual terminal id (if required)" />
          </div>
        </div>

        <button class="secondary" type="button" id="refundLookupButton">Fetch Transaction Details</button>

        <div class="result-box" id="refundLookupResult" style="display:none">
          <h3>Transaction Details</h3>
          <div class="result-grid">
            <div class="result-item"><strong>Transaction ID</strong><span id="vTxnId">-</span></div>
            <div class="result-item"><strong>Amount</strong><span id="vAmount">-</span></div>
            <div class="result-item"><strong>Currency</strong><span id="vCurrency">-</span></div>
            <div class="result-item"><strong>Approval Code</strong><span id="vApprovalCode">-</span></div>
            <div class="result-item"><strong>RRN</strong><span id="vRrn">-</span></div>
            <div class="result-item"><strong>Response Code</strong><span id="vResponseCode">-</span></div>
            <div class="result-item"><strong>Response Reason</strong><span id="vResponseReason">-</span></div>
            <div class="result-item"><strong>Status</strong><span id="vStatus">-</span></div>
          </div>
        </div>

        <div class="form-grid">
          <div class="section-label">Refund Action</div>
          <div class="field full">
            <label for="refundAmount">Refund Amount</label>
            <input id="refundAmount" type="number" min="0.01" step="0.01" placeholder="0.00" />
          </div>
        </div>

        <button class="submit" type="button" id="refundInitiateButton">Initiate Refund</button>
        <div class="status-note" id="refundActionResult"></div>
      </section>

          <ul>
            <li><span class="dot"></span><span>Secure payment processing</span></li>
            <li><span class="dot"></span><span>3D Secure authentication</span></li>
            <li><span class="dot"></span><span>Powered by bank payment gateway</span></li>
          </ul>
        </div>
      </section>
    </div>
  </div>
  <script>
    (function () {
      const form = document.getElementById('checkoutForm');
      const midInput = document.getElementById('merchantId');
      const amountInput = document.getElementById('amount');
      const customerNameInput = document.getElementById('customerName');
      const emailInput = document.getElementById('email');
      const currencyLabel = document.getElementById('currencyLabel');
      const currencyInput = document.getElementById('currency');
      const generateLinkButton = document.getElementById('generateLinkButton');
      const copyLinkButton = document.getElementById('copyLinkButton');
      const paymentLinkPanel = document.getElementById('paymentLinkPanel');
      const paymentLinkOutput = document.getElementById('paymentLinkOutput');
      const paymentLinkMeta = document.getElementById('paymentLinkMeta');
      const tabPayment = document.getElementById('tabPayment');
      const tabRefund = document.getElementById('tabRefund');
      const panelPayment = document.getElementById('panelPayment');
      const panelRefund = document.getElementById('panelRefund');

      const refundMerchantId = document.getElementById('refundMerchantId');
      const refundOriginalTxnId = document.getElementById('refundOriginalTxnId');
      const refundTerminalId = document.getElementById('refundTerminalId');
      const refundAmount = document.getElementById('refundAmount');
      const refundLookupButton = document.getElementById('refundLookupButton');
      const refundInitiateButton = document.getElementById('refundInitiateButton');
      const refundLookupResult = document.getElementById('refundLookupResult');
      const refundActionResult = document.getElementById('refundActionResult');

      const vTxnId = document.getElementById('vTxnId');
      const vAmount = document.getElementById('vAmount');
      const vCurrency = document.getElementById('vCurrency');
      const vApprovalCode = document.getElementById('vApprovalCode');
      const vRrn = document.getElementById('vRrn');
      const vResponseCode = document.getElementById('vResponseCode');
      const vResponseReason = document.getElementById('vResponseReason');
      const vStatus = document.getElementById('vStatus');

      let refundLookupData = null;

      const currencyCodeToName = {
        '840': 'USD',
        '356': 'INR'
      };

      async function updateCurrency() {
        const merchantId = (midInput.value || '').trim();
        if (!merchantId) {
          currencyInput.value = '';
          currencyLabel.textContent = '';
          return;
        }

        try {
          const res = await fetch('/api/merchant-currency?merchantId=' + encodeURIComponent(merchantId), {
            method: 'GET',
            headers: { 'Accept': 'application/json' }
          });

          if (!res.ok) {
            currencyInput.value = '';
            currencyLabel.textContent = '';
            return;
          }

          const data = await res.json();
          const code = (data && data.currency) ? String(data.currency) : '';
          currencyInput.value = code;
          const displayName = currencyCodeToName[code] || code;
          currencyLabel.textContent = displayName || '';
        } catch {
          currencyInput.value = '';
          currencyLabel.textContent = '';
        }
      }

      async function generatePaymentLink() {
        const merchantId = (midInput.value || '').trim();
        const amount = (amountInput.value || '').trim();

        if (!merchantId || !amount) {
          window.alert('Enter MID and amount first.');
          return;
        }

        generateLinkButton.disabled = true;
        generateLinkButton.textContent = 'Generating...';

        try {
          await updateCurrency();

          const res = await fetch('/api/payment-links', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Accept': 'application/json'
            },
            body: JSON.stringify({
              merchantId,
              amount,
              currency: currencyInput.value,
              customerName: (customerNameInput.value || '').trim(),
              email: (emailInput.value || '').trim()
            })
          });

          const data = await res.json();
          if (!res.ok || !data.paymentUrl) {
            throw new Error(data.error || 'Unable to generate payment link.');
          }

          paymentLinkOutput.value = data.paymentUrl;
          paymentLinkMeta.textContent = 'Currency: ' + data.currency + ' • Expires: ' + new Date(data.expiresAt).toLocaleString();
          paymentLinkPanel.classList.add('active');
        } catch (error) {
          window.alert(error.message || 'Unable to generate payment link.');
        } finally {
          generateLinkButton.disabled = false;
          generateLinkButton.textContent = 'Generate Payment Link';
        }
      }

      async function copyPaymentLink() {
        const value = paymentLinkOutput.value || '';
        if (!value) return;

        try {
          await navigator.clipboard.writeText(value);
          copyLinkButton.textContent = 'Copied';
          setTimeout(() => {
            copyLinkButton.textContent = 'Copy Link';
          }, 1500);
        } catch {
          paymentLinkOutput.focus();
          paymentLinkOutput.select();
        }
      }

      function switchTab(tab) {
        const showPayment = tab === 'payment';
        tabPayment.classList.toggle('active', showPayment);
        tabRefund.classList.toggle('active', !showPayment);
        panelPayment.classList.toggle('active', showPayment);
        panelRefund.classList.toggle('active', !showPayment);
      }

      function setRefundLookupView(data) {
        refundLookupData = data;
        vTxnId.textContent = data.txnId || '-';
        vAmount.textContent = data.amount || '-';
        vCurrency.textContent = data.currency || '-';
        vApprovalCode.textContent = data.approvalCode || '-';
        vRrn.textContent = data.rrn || '-';
        vResponseCode.textContent = data.responseCode || '-';
        vResponseReason.textContent = data.responseReason || '-';
        vStatus.textContent = data.status || '-';
        refundLookupResult.style.display = 'block';
      }

      async function lookupRefundTransaction() {
        const merchantId = (refundMerchantId.value || '').trim();
        const originalTxnId = (refundOriginalTxnId.value || '').trim();
        const terminalId = (refundTerminalId.value || '').trim();

        if (!merchantId || !originalTxnId) {
          window.alert('Merchant ID and Original Transaction ID are required.');
          return;
        }

        refundLookupButton.disabled = true;
        refundLookupButton.textContent = 'Fetching...';
        refundActionResult.textContent = '';

        try {
          const res = await fetch('/api/refund/lookup', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Accept': 'application/json'
            },
            body: JSON.stringify({
              merchantId,
              originalTxnId,
              terminalId
            })
          });

          const data = await res.json();
          if (!res.ok) {
            throw new Error(data.error || data.message || 'Lookup failed');
          }

          setRefundLookupView(data);
          refundActionResult.textContent = 'Transaction details fetched.';
        } catch (error) {
          refundLookupData = null;
          refundLookupResult.style.display = 'none';
          refundActionResult.textContent = error.message || 'Lookup failed';
        } finally {
          refundLookupButton.disabled = false;
          refundLookupButton.textContent = 'Fetch Transaction Details';
        }
      }

      async function initiateRefund() {
        const merchantId = (refundMerchantId.value || '').trim();
        const originalTxnId = (refundOriginalTxnId.value || '').trim();
        const amount = (refundAmount.value || '').trim();

        if (!merchantId || !originalTxnId || !amount) {
          window.alert('Merchant ID, Original Transaction ID and Refund Amount are required.');
          return;
        }

        refundInitiateButton.disabled = true;
        refundInitiateButton.textContent = 'Processing...';

        try {
          const res = await fetch('/api/refund/initiate', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Accept': 'application/json'
            },
            body: JSON.stringify({
              merchantId,
              originalTxnId,
              refundAmount: amount
            })
          });

          const data = await res.json();
          if (!res.ok) {
            throw new Error(data.error || data.message || 'Refund failed');
          }

          refundActionResult.textContent =
            'Status: ' + (data.status || 'UNKNOWN') +
            ' | Approval: ' + (data.approvalCode || '-') +
            ' | RRN: ' + (data.rrn || '-') +
            ' | Message: ' + (data.responseReason || data.responseCode || '-');
        } catch (error) {
          refundActionResult.textContent = error.message || 'Refund failed';
        } finally {
          refundInitiateButton.disabled = false;
          refundInitiateButton.textContent = 'Initiate Refund';
        }
      }

      midInput.addEventListener('input', updateCurrency);
      generateLinkButton.addEventListener('click', generatePaymentLink);
      copyLinkButton.addEventListener('click', copyPaymentLink);
      tabPayment.addEventListener('click', () => switchTab('payment'));
      tabRefund.addEventListener('click', () => switchTab('refund'));
      refundLookupButton.addEventListener('click', lookupRefundTransaction);
      refundInitiateButton.addEventListener('click', initiateRefund);
      updateCurrency();
    })();
  </script>
</body>
</html>`;
}

function appendResultParams(targetUrl, { txnId, status }) {
  try {
    const u = new URL(targetUrl);
    u.searchParams.set('txnId', txnId);
    u.searchParams.set('status', status);
    return u.toString();
  } catch {
    return '';
  }
}

async function handleInitiate(req, res) {
  const raw = await parseBody(req);
  const contentType = (req.headers['content-type'] || '').toLowerCase();
  const input = parseRawPayload(raw, contentType);

  const merchantId = String(input.merchantId || MERCHANT_ID_DEFAULT || '').trim();
  const amount = String(input.amount || '').trim();
  const currencyInput = String(input.currency || '').trim();
  const orderRefInput = String(input.orderRef || '').trim();
  const customerRefInput = String(input.customerRef || '').trim();
  const customerName = String(input.customerName || '').trim();
  const email = String(input.email || '').trim();
  const mobilePhone = String(input.mobilePhone || '').trim();
  const successReturnUrl = String(input.successReturnUrl || '').trim();
  const failReturnUrl = String(input.failReturnUrl || '').trim();
  const txnId = String(input.txnId || generateTxnId()).trim();
  const orderRef = orderRefInput || `ORD-${txnId}`;
  const customerRef = customerRefInput || `CUST-${txnId.slice(-8)}`;

  const missing = [];
  if (!merchantId) missing.push('merchantId');
  if (!amount) missing.push('amount');
  if (!txnId) missing.push('txnId');

  if (missing.length) {
    return html(
      res,
      400,
      renderMessagePage('Validation error', 'Required fields are missing.', { missingFields: missing })
    );
  }

  const existing = await getTransaction(txnId);
  if (existing) {
    return html(
      res,
      409,
      renderMessagePage('Duplicate transaction ID', 'Use a new transaction ID.', { txnId })
    );
  }

  let amountMinor;
  try {
    amountMinor = amountToMinorUnits(amount);
  } catch (error) {
    return html(res, 400, renderMessagePage('Invalid amount', error.message, { amount }));
  }

  const currencyResolved = normalizeCurrency(currencyInput)
    ? { currency: normalizeCurrency(currencyInput), source: 'request' }
    : await resolveMerchantCurrency(merchantId);
  const currency = currencyResolved.currency;

  if (!currency) {
    return html(
      res,
      400,
      renderMessagePage(
        'Currency not configured',
        'No currency is configured for this MID. Add the MID to the merchant currency database first.',
        { merchantId }
      )
    );
  }

  const requestBaseUrl = getRequestBaseUrl(req);
  const purchDate = formatPurchDate(new Date());
  const callbackUrl = `${requestBaseUrl}/api/callback`;

  const keys = createRsaKeyPair();

  let mkReq;
  try {
    mkReq = await doMkReq({
      merchantId,
      purchaseId: txnId,
      merchantPublicKeyBase64Url: keys.publicKeyBase64Url,
      merchantPrivateKeyPem: keys.privateKeyPem,
    });
  } catch (error) {
    console.error('[Cardzone][initiate] mkReq failed:', error.message);
    return html(res, 502, renderMessagePage('Unable to start payment', error.message));
  }

  const mkReqRes = mkReq.responsePayload;
  if (String(mkReqRes.errorCode || '').trim() !== '000' || !mkReqRes.pubKey) {
    console.error('[Cardzone][initiate] mkReq error response:', JSON.stringify(mkReqRes));
    return html(
      res,
      400,
      renderMessagePage('mkReq failed', 'Cardzone did not provide a usable key exchange response.', mkReqRes)
    );
  }

  const mpiReq = {
    MPI_TRANS_TYPE: 'SALES',
    MPI_MERC_ID: merchantId,
    MPI_TRXN_ID: txnId,
    MPI_PURCH_DATE: purchDate,
    MPI_PURCH_CURR: currency,
    MPI_PURCH_AMT: amountMinor,
    MPI_RESPONSE_LINK: callbackUrl,
  };

  if (email) mpiReq.MPI_EMAIL = email;
  // NOTE: Phone fields (MPI_MOBILE_PHONE, MPI_HOME_PHONE, MPI_WORK_PHONE, etc.) 
  // are intentionally excluded to avoid MAC verification failures. 
  // Will be re-enabled once correct field order and null-handling is confirmed with Cardzone.

  const mpiReqSignInput = mpiReqSignString(mpiReq);
  const mpiMac = signSha256WithRsaBase64Url(mpiReqSignInput, keys.privateKeyPem);
  mpiReq.MPI_MAC = mpiMac;

  const mercReqUrl = CARDZONE_REDIRECT_URL;
  console.log('Returning auto-submit HTML to Cardzone');
  console.log('Cardzone URL:', mercReqUrl);
  console.log('[Cardzone][mercReq] endpoint=', mercReqUrl);
  console.log('[Cardzone][mercReq] flow=hosted-page html-form-post=true');
  logMpiReqSigningDetails(mpiReq, mpiReqSignInput, mpiMac);

  const tx = {
    txnId,
    orderRef,
    customerRef,
    customerName,
    merchantId,
    amountMinor,
    amountMajor: amount,
    currency,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    successReturnUrl,
    failReturnUrl,
    security: {
      merchantPrivateKeyPem: keys.privateKeyPem,
      merchantPublicKeyBase64Url: keys.publicKeyBase64Url,
      cardzonePublicKeyBase64Url: mkReqRes.pubKey,
    },
    mkReq: {
      request: mkReq.requestPayload,
      response: mkReqRes,
    },
    mercReq: {
      action: mercReqUrl,
      requestFields: mpiReq,
      signInput: mpiReqSignInput,
    },
    callback: null,
    inquiry: null,
    finalResult: null,
    macVerification: null,
    status: 'REDIRECTED_TO_HOSTED_PAGE',
  };

  await saveTransaction(tx);
  return html(res, 200, renderAutoPostPage(mercReqUrl, mpiReq));
}

async function handleCallback(req, res) {
  const raw = await parseBody(req);
  const contentType = (req.headers['content-type'] || '').toLowerCase();
  const fields = parseRawPayload(raw, contentType);

  const txnId = String(fields.MPI_TRXN_ID || fields.mpiTrxnId || fields.trxnId || fields.txnId || '').trim();
  if (!txnId) {
    return html(res, 400, renderMessagePage('Callback rejected', 'Missing MPI_TRXN_ID in callback payload.'));
  }

  const tx = await getTransaction(txnId);
  if (!tx) {
    return html(
      res,
      404,
      renderMessagePage('Transaction not found', 'No transaction exists for the callback reference.', { txnId })
    );
  }

  console.log('Callback received for txn:', txnId);

  const hasMac = !!fields.MPI_MAC;
  const verifyInput = mpiResVerifyString(fields);
  const macVerified =
    hasMac && !!tx.security?.cardzonePublicKeyBase64Url
      ? verifySha256WithRsaBase64Url(verifyInput, fields.MPI_MAC, tx.security.cardzonePublicKeyBase64Url)
      : false;

  console.log('MPI_ERROR_CODE:', fields.MPI_ERROR_CODE || '');
  console.log('MPI_ERROR_DESC:', fields.MPI_ERROR_DESC || '');
  console.log('MPI_APPR_CODE:', fields.MPI_APPR_CODE || '');
  console.log('MPI_RRN:', fields.MPI_RRN || '');
  console.log('MPI_REFERRAL_CODE:', fields.MPI_REFERRAL_CODE || '');
  console.log('MPI_BIN:', fields.MPI_BIN || '');
  console.log('MAC verified:', macVerified);

  tx.callback = {
    receivedAt: new Date().toISOString(),
    method: req.method,
    contentType,
    fields,
    rawResponseFields: { ...fields },
    rawPayload: raw,
  };
  tx.macVerification = {
    hasMac,
    macVerified,
    verifyInput,
    verifyNote: hasMac ? (macVerified ? 'MPIRes MAC verified successfully' : 'MPIRes MAC verification failed') : 'No MPI_MAC received',
  };
  const callbackResultTrusted = !hasMac || macVerified;
  let finalResult = callbackResultTrusted
    ? buildFinalResultRecord({
        fields,
        source: 'callback',
        resolvedAt: tx.callback.receivedAt,
      })
    : null;

  if (!callbackResultTrusted || !hasSufficientFinalResult(finalResult)) {
    try {
      const inquiry = await doInquiry(tx, txnId);
      tx.inquiry = inquiry;

      const inquiryResult = buildFinalResultRecord({
        fields: inquiry.responseFields,
        source: 'inquiry',
        resolvedAt: inquiry.requestedAt,
      });
      const inquiryResultTrusted = !inquiry.macVerification?.hasMac || inquiry.macVerification.macVerified;

      if (inquiryResultTrusted && hasSufficientFinalResult(inquiryResult)) {
        finalResult = inquiryResult;
      }
    } catch (error) {
      tx.inquiry = {
        requestedAt: new Date().toISOString(),
        endpoint: CARDZONE_INQUIRY_URL,
        error: error.message,
      };
      console.error('[Cardzone][inquiry] failed for txn', txnId, error.message);
    }
  }

  tx.finalResult = finalResult;
  const finalStatus = mapTransactionLifecycleStatus({
    callbackReceived: true,
    finalResult,
  });
  tx.status = finalStatus;
  tx.updatedAt = new Date().toISOString();

  await saveTransaction(tx);

  console.log('[Cardzone][callback] txnId=', txnId, 'status=', finalStatus, 'macVerified=', macVerified);

  if (finalStatus === 'PENDING') {
    return html(
      res,
      202,
      renderMessagePage(
        'Payment processing',
        'Payment is still processing. Please wait or refresh.',
        {
          txnId,
          status: finalStatus,
          callbackReceived: true,
        }
      )
    );
  }

  return html(res, 200, renderResultPage(tx, finalStatus, finalResult));
}

async function handleReturn(req, res) {
  const u = new URL(req.url, `http://${req.headers.host}`);
  let txnId = u.searchParams.get('txnId');

  if (req.method === 'POST' && !txnId) {
    const raw = await parseBody(req);
    const contentType = (req.headers['content-type'] || '').toLowerCase();
    const fields = parseRawPayload(raw, contentType);
    txnId = fields.MPI_TRXN_ID || fields.txnId || '';
  }

  if (!txnId) {
    return html(
      res,
      400,
      renderMessagePage('No transaction reference received', 'Provide txnId in query string or POST body.')
    );
  }

  const tx = await getTransaction(txnId);
  if (!tx) {
    return html(
      res,
      404,
      renderMessagePage('Transaction not found', 'No transaction record found for this reference.', { txnId })
    );
  }

  const callbackReceived = !!tx.callback;
  const callbackResultTrusted = !tx.macVerification?.hasMac || !!tx.macVerification?.macVerified;
  let finalResult = tx.finalResult;

  if (finalResult?.source === 'callback' && !callbackResultTrusted) {
    finalResult = null;
  }

  if (!finalResult && callbackResultTrusted) {
    finalResult = buildFinalResultRecord({
      fields: tx.callback?.fields,
      source: 'callback',
      resolvedAt: tx.callback?.receivedAt,
    });
  }

  if (callbackReceived && (!callbackResultTrusted || !hasSufficientFinalResult(finalResult))) {
    try {
      const inquiry = await doInquiry(tx, tx.txnId);
      tx.inquiry = inquiry;

      const inquiryResult = buildFinalResultRecord({
        fields: inquiry.responseFields,
        source: 'inquiry',
        resolvedAt: inquiry.requestedAt,
      });
      const inquiryResultTrusted = !inquiry.macVerification?.hasMac || inquiry.macVerification.macVerified;

      if (inquiryResultTrusted && hasSufficientFinalResult(inquiryResult)) {
        finalResult = inquiryResult;
        tx.finalResult = inquiryResult;
        tx.status = mapTransactionLifecycleStatus({
          callbackReceived,
          finalResult: inquiryResult,
        });
        tx.updatedAt = new Date().toISOString();
        await saveTransaction(tx);
      }
    } catch (error) {
      if (!tx.inquiry?.error) {
        tx.inquiry = {
          requestedAt: new Date().toISOString(),
          endpoint: CARDZONE_INQUIRY_URL,
          error: error.message,
        };
        tx.updatedAt = new Date().toISOString();
        await saveTransaction(tx);
      }
      console.error('[Cardzone][return][inquiry] failed for txn', tx.txnId, error.message);
    }
  }

  const effectiveStatus = mapTransactionLifecycleStatus({
    callbackReceived,
    finalResult,
  });
  const hasFinalState = effectiveStatus !== 'PENDING';

  if (!hasFinalState) {
    return html(
      res,
      202,
      renderMessagePage(
        'Payment processing',
        'Payment is still processing. Please wait or refresh.',
        {
          txnId: tx.txnId,
          status: effectiveStatus,
          callbackReceived,
        }
      )
    );
  }

  return html(res, 200, renderResultPage(tx, effectiveStatus, finalResult));
}

async function handleTxDebug(req, res, txnId) {
  const tx = await getTransaction(txnId);
  if (!tx) {
    return json(res, 404, {
      error: 'Transaction not found',
      txnId,
    });
  }

  return json(res, 200, {
    txnId: tx.txnId,
    status: tx.status,
    callbackReceived: !!tx.callback,
    mpiErrorCode: tx.finalResult?.responseCode || tx.callback?.fields?.MPI_ERROR_CODE || null,
    mpiApprovalCode: tx.finalResult?.authorizationCode || tx.callback?.fields?.MPI_APPR_CODE || null,
    mpiRrn: tx.finalResult?.referenceNumber || tx.callback?.fields?.MPI_RRN || null,
    finalResultSource: tx.finalResult?.source || null,
    macVerified: tx.macVerification?.macVerified ?? null,
  });
}

async function handleMerchantCurrency(req, res) {
  const u = new URL(req.url, `http://${req.headers.host}`);
  const merchantId = String(u.searchParams.get('merchantId') || '').trim();

  if (!merchantId) {
    return json(res, 400, {
      error: 'merchantId is required',
    });
  }

  const resolved = await resolveMerchantCurrency(merchantId);
  if (!resolved.currency) {
    return json(res, 404, {
      merchantId,
      error: 'Currency not configured for this MID',
      source: resolved.source,
    });
  }

  return json(res, 200, {
    merchantId,
    currency: resolved.currency,
    source: resolved.source,
  });
}

async function handleCreatePaymentLink(req, res) {
  const raw = await parseBody(req);
  const contentType = (req.headers['content-type'] || '').toLowerCase();
  const input = parseRawPayload(raw, contentType);

  const merchantId = String(input.merchantId || '').trim();
  const amount = String(input.amount || '').trim();
  const customerName = String(input.customerName || '').trim();
  const email = String(input.email || '').trim();
  const mobilePhone = String(input.mobilePhone || '').trim();

  if (!merchantId || !amount) {
    return json(res, 400, { error: 'merchantId and amount are required' });
  }

  try {
    amountToMinorUnits(amount);
  } catch (error) {
    return json(res, 400, { error: error.message });
  }

  const currencyInput = String(input.currency || '').trim();
  const currencyResolved = normalizeCurrency(currencyInput)
    ? { currency: normalizeCurrency(currencyInput), source: 'request' }
    : await resolveMerchantCurrency(merchantId);

  if (!currencyResolved.currency) {
    return json(res, 400, {
      error: 'Currency not configured for this MID',
      merchantId,
      source: currencyResolved.source,
    });
  }

  const token = generatePaymentLinkToken();
  const createdAt = new Date();
  const expiresAt = new Date(createdAt.getTime() + PAYMENT_LINK_TTL_MS);
  const baseUrl = getRequestBaseUrl(req);

  await savePaymentLink({
    token,
    merchantId,
    amount,
    currency: currencyResolved.currency,
    customerName,
    email,
    mobilePhone,
    createdAt: createdAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
  });

  return json(res, 200, {
    token,
    paymentUrl: `${baseUrl}/pay/${encodeURIComponent(token)}`,
    currency: currencyResolved.currency,
    currencySource: currencyResolved.source,
    expiresAt: expiresAt.toISOString(),
  });
}

async function handleRefundLookup(req, res) {
  const raw = await parseBody(req);
  const contentType = (req.headers['content-type'] || '').toLowerCase();
  const input = parseRawPayload(raw, contentType);

  const merchantId = String(input.merchantId || '').trim();
  const originalTxnId = String(input.originalTxnId || '').trim();
  const terminalId = String(input.terminalId || '').trim();

  if (!merchantId || !originalTxnId) {
    return json(res, 400, {
      error: 'merchantId and originalTxnId are required',
    });
  }

  async function getLocalSummary() {
    const localTx = await findStoredTransactionForRefund(merchantId, originalTxnId);
    if (!localTx) return null;
    if (String(localTx.merchantId || '').trim() !== merchantId) return null;
    return mapStoredTransactionToRefundLookup(localTx, originalTxnId);
  }

  try {
    const inquiry = await lookupTransactionForRefund({
      merchantId,
      originalTxnId,
      terminalId,
    });

    if (hasRefundLookupDetails(inquiry.summary)) {
      return json(res, 200, inquiry.summary);
    }

    const localSummary = await getLocalSummary();
    if (localSummary) {
      return json(res, 200, localSummary);
    }

    return json(res, 200, {
      txnId: originalTxnId,
      amount: '',
      currency: '',
      approvalCode: '',
      rrn: '',
      responseCode: '',
      responseReason: 'Inquiry completed but no transaction details were returned by gateway',
      status: 'UNKNOWN',
    });
  } catch (error) {
    const localSummary = await getLocalSummary();
    if (localSummary) {
      return json(res, 200, localSummary);
    }

    console.error('[Cardzone][refund][lookup] failed:', error.message);
    return json(res, 502, {
      error: 'Unable to lookup transaction for refund',
      message: error.message,
    });
  }
}

async function handleRefundInitiate(req, res) {
  const raw = await parseBody(req);
  const contentType = (req.headers['content-type'] || '').toLowerCase();
  const input = parseRawPayload(raw, contentType);

  const merchantId = String(input.merchantId || '').trim();
  const originalTxnId = String(input.originalTxnId || '').trim();
  const refundAmount = String(input.refundAmount || '').trim();

  if (!merchantId || !originalTxnId || !refundAmount) {
    return json(res, 400, {
      error: 'merchantId, originalTxnId, and refundAmount are required',
    });
  }

  let refundAmountMinor;
  try {
    refundAmountMinor = Number.parseInt(amountToMinorUnits(refundAmount), 10);
  } catch (error) {
    return json(res, 400, {
      error: error.message,
    });
  }

  try {
    let original = null;

    try {
      const inquiry = await lookupTransactionForRefund({
        merchantId,
        originalTxnId,
        terminalId: '',
      });
      if (hasRefundLookupDetails(inquiry.summary)) {
        original = inquiry.summary;
      }
    } catch {
      // Fallback to local transaction record below
    }

    if (!original) {
      const localTx = await findStoredTransactionForRefund(merchantId, originalTxnId);
      if (localTx && String(localTx.merchantId || '').trim() === merchantId) {
        original = mapStoredTransactionToRefundLookup(localTx, originalTxnId);
      }
    }

    if (!original || !original.txnId) {
      return json(res, 400, {
        error: 'originalTxnId does not exist',
      });
    }

    const originalAmountMinor = toMinorUnitsFromGatewayAmount(original.amount);
    if (!originalAmountMinor) {
      return json(res, 400, {
        error: 'Original transaction amount is unavailable for refund validation',
      });
    }

    if (!isApprovedResponseCode(original.responseCode) || !original.approvalCode) {
      return json(res, 400, {
        error: 'Original transaction is not successful and cannot be refunded',
        responseCode: original.responseCode,
        responseReason: original.responseReason,
      });
    }

    if (refundAmountMinor > originalAmountMinor) {
      return json(res, 400, {
        error: 'refundAmount cannot be greater than original transaction amount',
        originalAmount: original.amount,
        refundAmountMinor: String(refundAmountMinor),
      });
    }

    const refund = await initiateRefundRequest({
      merchantId,
      originalTxnId,
      refundAmountMinor,
    });

    return json(res, 200, refund.result);
  } catch (error) {
    console.error('[Cardzone][refund][initiate] failed:', error.message);
    return json(res, 502, {
      error: 'Unable to initiate refund',
      message: error.message,
    });
  }
}

async function handlePaymentLinkLanding(req, res, token) {
  const paymentLink = await getPaymentLink(token);
  if (!paymentLink) {
    return html(res, 404, renderMessagePage('Payment link not found', 'This payment link does not exist or is no longer available.'));
  }

  if (paymentLink.expiresAt && Date.parse(paymentLink.expiresAt) < Date.now()) {
    return html(res, 410, renderMessagePage('Payment link expired', 'This payment link has expired. Please request a new one.'));
  }

  return html(
    res,
    200,
    renderAutoPostPage('/api/initiate', {
      merchantId: paymentLink.merchantId,
      amount: paymentLink.amount,
      currency: paymentLink.currency,
      customerName: paymentLink.customerName,
      email: paymentLink.email,
      mobilePhone: paymentLink.mobilePhone,
    })
  );
}

function handleHealth(req, res) {
  return json(res, 200, {
    ok: true,
    service: 'cardzone-payment-backend',
    timestamp: new Date().toISOString(),
  });
}

module.exports = async function handler(req, res) {
  try {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Accept, Authorization');

    if (req.method === 'OPTIONS') {
      res.statusCode = 204;
      return res.end();
    }

    const u = new URL(req.url, `http://${req.headers.host}`);

    if (req.method === 'GET' && (u.pathname === '/favicon.ico' || u.pathname === '/favicon.png')) {
      res.statusCode = 204;
      res.setHeader('Cache-Control', 'public, max-age=86400');
      return res.end();
    }

    if (req.method === 'GET' && (u.pathname === '/' || u.pathname === '/checkout')) {
      return html(res, 200, renderPublicCheckoutPage(getRequestBaseUrl(req)));
    }

    if (req.method === 'GET' && (u.pathname === '/api' || u.pathname === '/developer')) {
      return html(res, 200, renderDeveloperHome(getRequestBaseUrl(req)));
    }

    if (req.method === 'POST' && (u.pathname === '/api/initiate' || u.pathname === '/initiate')) {
      return await handleInitiate(req, res);
    }

    if (req.method === 'POST' && (u.pathname === '/api/payment-links' || u.pathname === '/payment-links')) {
      return await handleCreatePaymentLink(req, res);
    }

    if (req.method === 'POST' && (u.pathname === '/api/refund/lookup' || u.pathname === '/api/refund/lookup/' || u.pathname === '/refund/lookup')) {
      return await handleRefundLookup(req, res);
    }

    if (req.method === 'POST' && (u.pathname === '/api/refund/initiate' || u.pathname === '/api/refund/initiate/' || u.pathname === '/refund/initiate')) {
      return await handleRefundInitiate(req, res);
    }

    if (req.method === 'GET' && (u.pathname === '/api/merchant-currency' || u.pathname === '/merchant-currency')) {
      return await handleMerchantCurrency(req, res);
    }

    if (req.method === 'GET' && u.pathname.startsWith('/pay/')) {
      const parts = u.pathname.split('/').filter(Boolean);
      const token = parts[parts.length - 1] || '';
      return await handlePaymentLinkLanding(req, res, token);
    }

    if (req.method === 'GET' && (u.pathname === '/callback' || u.pathname === '/api/callback')) {
      const txnId =
        u.searchParams.get('txnId') ||
        u.searchParams.get('MPI_TRXN_ID') ||
        u.searchParams.get('trxnId') ||
        '';
      const returnPath = txnId ? `/api/return?txnId=${encodeURIComponent(txnId)}` : '/api/return';
      return redirect(res, returnPath);
    }

    if (req.method === 'POST' && (u.pathname === '/callback' || u.pathname === '/api/callback')) {
      return await handleCallback(req, res);
    }

    if ((req.method === 'GET' || req.method === 'POST') && (u.pathname === '/return' || u.pathname === '/api/return')) {
      return await handleReturn(req, res);
    }

    if (req.method === 'GET' && (u.pathname.startsWith('/api/tx/') || u.pathname.startsWith('/tx/'))) {
      const parts = u.pathname.split('/').filter(Boolean);
      const txnId = parts[parts.length - 1] || '';
      if (!txnId) {
        return json(res, 400, { error: 'txnId is required' });
      }
      return await handleTxDebug(req, res, txnId);
    }

    if (req.method === 'GET' && (u.pathname === '/health' || u.pathname === '/api/health')) {
      return handleHealth(req, res);
    }

    if (u.pathname === '/start-payment') {
      return html(
        res,
        410,
        renderMessagePage('Deprecated route', 'Use POST /api/initiate from merchant checkout page.')
      );
    }

    return html(res, 404, renderMessagePage('Not Found', 'The requested endpoint does not exist.'));
  } catch (err) {
    console.error('[Cardzone][server-error]', err);
    return html(res, 500, renderMessagePage('Server error', err.message));
  }
};
