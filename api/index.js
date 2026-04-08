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
const CARDZONE_PROFILE_URL = process.env.CARDZONE_PROFILE_URL || '';
const MERCHANT_CURRENCY_DB_PATH =
  process.env.MERCHANT_CURRENCY_DB_PATH || path.join(process.cwd(), 'data', 'merchant-currency.json');
const ENABLE_MKREQ_MAC = process.env.ENABLE_MKREQ_MAC === 'true';
const TEMP_DIR = process.env.VERCEL ? '/tmp' : path.join(os.tmpdir(), 'cardzone-backend');
const PAYMENT_LINK_TTL_MS = Number(process.env.PAYMENT_LINK_TTL_MS || 7 * 24 * 60 * 60 * 1000);

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

function mapFinalStatus({ hasMac, macVerified, errorCode, approvalCode }) {
  if (hasMac && !macVerified) return 'VERIFY_FAILED';
  const ec = String(errorCode || '').trim();
  const appr = String(approvalCode || '').trim();
  if (hasMac && macVerified && ec === '000' && appr) return 'SUCCESS';
  return 'FAILED';
}

function mapTransactionLifecycleStatus({ callbackReceived, hasMac, macVerified, errorCode, approvalCode }) {
  if (!callbackReceived) return 'PENDING';
  return mapFinalStatus({ hasMac, macVerified, errorCode, approvalCode });
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

function renderDeveloperHome(baseUrl) {
  return `<!doctype html>
<html>
<head><meta charset="utf-8"><title>Cardzone Payment Backend</title></head>
<body style="font-family:Arial,sans-serif;padding:24px">
  <h1>Cardzone payment backend is running</h1>
  <p>This deployment is backend-only. Customer checkout UI must be hosted on merchant website.</p>
  <ul>
    <li>POST ${escapeHtml(baseUrl)}/api/initiate</li>
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
    @media (max-width:900px){
      .form-grid{grid-template-columns:1fr}
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

      <form id="checkoutForm" method="post" action="/api/initiate" autocomplete="on">
        <div class="form-grid">
          <div class="section-label">Payment Details</div>

          <div class="field">
            <label for="merchantId">Merchant ID</label>
            <input id="merchantId" name="merchantId" required placeholder="Enter registered MID" value="${escapeHtml(MERCHANT_ID_DEFAULT)}" />
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

        <div class="trust">
          <ul>
            <li><span class="dot"></span><span>Secure payment processing</span></li>
            <li><span class="dot"></span><span>3D Secure authentication</span></li>
            <li><span class="dot"></span><span>Powered by bank payment gateway</span></li>
          </ul>
        </div>
      </form>
    </section>
  </div>
  <script>
    (function () {
      const midInput = document.getElementById('merchantId');
      const currencyLabel = document.getElementById('currencyLabel');
      const currencyInput = document.getElementById('currency');

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

      midInput.addEventListener('input', updateCurrency);
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

  const finalStatus = mapTransactionLifecycleStatus({
    callbackReceived: true,
    hasMac,
    macVerified,
    errorCode: fields.MPI_ERROR_CODE,
    approvalCode: fields.MPI_APPR_CODE,
  });

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
  tx.status = finalStatus;
  tx.updatedAt = new Date().toISOString();

  await saveTransaction(tx);

  console.log('[Cardzone][callback] txnId=', txnId, 'status=', finalStatus, 'macVerified=', macVerified);

  return html(
    res,
    200,
    renderMessagePage('Payment callback received', 'Callback processed successfully.', {
      txnId,
      status: finalStatus,
      macVerified,
    })
  );
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
  const effectiveStatus = mapTransactionLifecycleStatus({
    callbackReceived,
    hasMac: !!tx.callback?.fields?.MPI_MAC,
    macVerified: !!tx.macVerification?.macVerified,
    errorCode: tx.callback?.fields?.MPI_ERROR_CODE,
    approvalCode: tx.callback?.fields?.MPI_APPR_CODE,
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

  return html(
    res,
    200,
    renderMessagePage(
      `Payment Result: ${effectiveStatus}`,
      tx.macVerification?.macVerified && effectiveStatus === 'FAILED'
        ? 'Integration succeeded, but the transaction was declined by Cardzone/host.'
        : 'Payment status resolved from backend transaction record.',
      {
        integrationStatus: tx.macVerification?.macVerified
          ? 'INTEGRATION_SUCCESS'
          : effectiveStatus === 'VERIFY_FAILED'
            ? 'INTEGRATION_VERIFY_FAILED'
            : 'INTEGRATION_PENDING_OR_NOT_VERIFIED',
        txnId: tx.txnId,
        status: effectiveStatus,
        amountMinor: tx.amountMinor,
        currency: tx.currency,
        orderRef: tx.orderRef,
        merchantId: tx.merchantId,
        callbackReceived,
        macVerified: tx.macVerification?.macVerified ?? null,
        MPI_ERROR_CODE: tx.callback?.fields?.MPI_ERROR_CODE || null,
        MPI_ERROR_DESC: tx.callback?.fields?.MPI_ERROR_DESC || null,
        MPI_APPR_CODE: tx.callback?.fields?.MPI_APPR_CODE || null,
        MPI_RRN: tx.callback?.fields?.MPI_RRN || null,
        MPI_REFERRAL_CODE: tx.callback?.fields?.MPI_REFERRAL_CODE || null,
        MPI_BIN: tx.callback?.fields?.MPI_BIN || null,
        allResponseFields: tx.callback?.rawResponseFields || tx.callback?.fields || {},
      }
    )
  );
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
    mpiErrorCode: tx.callback?.fields?.MPI_ERROR_CODE || null,
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
