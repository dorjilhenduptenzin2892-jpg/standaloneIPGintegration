const crypto = require('crypto');
const { URL } = require('url');
const fs = require('fs').promises;
const path = require('path');

const MERCHANT_ID = process.env.MERCHANT_ID || '863990030700270';
const CARDZONE_MKREQ_URL = process.env.CARDZONE_MKREQ_URL || 'https://uatczsecure.bob.bt/3dss/mkReq';
const CARDZONE_REDIRECT_URL =
  process.env.CARDZONE_REDIRECT_URL ||
  process.env.CARDZONE_MERCREQ_URL ||
  'https://uatczsecure.bob.bt/3dss/mercReq';
const CARDZONE_PROFILE_URL = process.env.CARDZONE_PROFILE_URL || '';
const RESPONSE_TYPE = process.env.RESPONSE_TYPE || 'STRING';
const DEFAULT_CURRENCY = process.env.DEFAULT_CURRENCY || '064';
const ENABLE_MKREQ_MAC = process.env.ENABLE_MKREQ_MAC === 'true';
const MKREQ_KEY_EXCHANGE_PRESTORED = process.env.MKREQ_KEY_EXCHANGE_PRESTORED === 'true';
const MPIREQ_INCLUDE_RESPONSE_LINK_IN_MAC = process.env.MPIREQ_INCLUDE_RESPONSE_LINK_IN_MAC === 'true';
const TEMP_DIR = '/tmp'; // Vercel uses /tmp for temp storage

const txStore = new Map();

function getRequestBaseUrl(req) {
  if (process.env.CALLBACK_BASE_URL) return process.env.CALLBACK_BASE_URL;
  const proto = (req.headers['x-forwarded-proto'] || 'https').toString().split(',')[0].trim();
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
  if (!Number.isFinite(n) || n <= 0) throw new Error('Invalid amount');
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

    const sig = Buffer.from(
      signatureBase64Url.replace(/-/g, '+').replace(/_/g, '/'),
      'base64'
    );
    return verifier.verify(publicKey, sig);
  } catch {
    return false;
  }
}

function mkReqSignString({ merchantId, purchaseId, pubKey }) {
  return `${merchantId || ''}${purchaseId || ''}${pubKey || ''}`;
}

function mpiReqSignString(fields, options = {}) {
  const includeResponseLink = !!options.includeResponseLink;
  const lineItems = Array.isArray(fields.MPI_LINE_ITEM) ? fields.MPI_LINE_ITEM : [];
  const flattenedLineItems = lineItems
    .map(item => `${item.MPI_ITEM_ID || ''}${item.MPI_ITEM_REMARK || ''}${item.MPI_ITEM_QUANTITY || ''}${item.MPI_ITEM_AMOUNT || ''}${item.MPI_ITEM_CURRENCY || ''}`)
    .join('');

  const signParts = [
    fields.MPI_TRANS_TYPE,
    fields.MPI_MERC_ID,
    fields.MPI_PAN,
    fields.MPI_CARD_HOLDER_NAME,
    fields.MPI_PAN_EXP,
    fields.MPI_CVV2,
    fields.MPI_TRXN_ID,
    fields.MPI_ORI_TRXN_ID,
    fields.MPI_PURCH_DATE,
    fields.MPI_PURCH_CURR,
    fields.MPI_PURCH_AMT,
    fields.MPI_ADDR_MATCH,
    fields.MPI_BILL_ADDR_CITY,
    fields.MPI_BILL_ADDR_STATE,
    fields.MPI_BILL_ADDR_CNTRY,
    fields.MPI_BILL_ADDR_POSTCODE,
    fields.MPI_BILL_ADDR_LINE1,
    fields.MPI_BILL_ADDR_LINE2,
    fields.MPI_BILL_ADDR_LINE3,
    fields.MPI_SHIP_ADDR_CITY,
    fields.MPI_SHIP_ADDR_STATE,
    fields.MPI_SHIP_ADDR_CNTRY,
    fields.MPI_SHIP_ADDR_POSTCODE,
    fields.MPI_SHIP_ADDR_LINE1,
    fields.MPI_SHIP_ADDR_LINE2,
    fields.MPI_SHIP_ADDR_LINE3,
    fields.MPI_EMAIL,
    fields.MPI_HOME_PHONE,
    fields.MPI_HOME_PHONE_CC,
    fields.MPI_WORK_PHONE,
    fields.MPI_WORK_PHONE_CC,
    fields.MPI_MOBILE_PHONE,
    fields.MPI_MOBILE_PHONE_CC,
    flattenedLineItems,
    fields.MPI_RESPONSE_TYPE,
  ];

  if (includeResponseLink) {
    signParts.push(fields.MPI_RESPONSE_LINK);
  }

  return signParts.map(v => v || '').join('');
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

function mapTransactionStatus({ callbackReceived, hasMac, macVerified, errorCode, approvalCode }) {
  if (!callbackReceived) return 'PENDING';
  if (hasMac && !macVerified) return 'VERIFY_FAILED';

  const ec = String(errorCode || '').trim();
  const appr = String(approvalCode || '').trim();
  if (hasMac && macVerified && ec === '000' && appr) return 'SUCCESS';
  return 'FAILED';
}

async function doMkReq({ merchantId, purchaseId, merchantPublicKeyBase64Url, merchantPrivateKeyPem }) {
  const payload = {
    merchantId,
    purchaseId,
    pubKey: merchantPublicKeyBase64Url,
  };

  const includeMkReqMac = ENABLE_MKREQ_MAC && MKREQ_KEY_EXCHANGE_PRESTORED;
  if (includeMkReqMac) {
    payload.mac = signSha256WithRsaBase64Url(mkReqSignString(payload), merchantPrivateKeyPem);
  }

  console.log('[Cardzone][mkReq] method=POST contentType=application/json includeMac=', includeMkReqMac);
  if (!includeMkReqMac) {
    console.log('[Cardzone][mkReq] mac omitted (requires pre-stored merchant public key at Cardzone/BOB).');
  }

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

  return data;
}

function normalizeCurrency(value) {
  const v = String(value || '').trim();
  return /^\d{3}$/.test(v) ? v : '';
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
  try {
    const url = CARDZONE_PROFILE_URL.includes('{merchantId}')
      ? CARDZONE_PROFILE_URL.replace('{merchantId}', encodeURIComponent(merchantId))
      : CARDZONE_PROFILE_URL;

    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ merchantId }),
    });

    const text = await r.text();
    try {
      return JSON.parse(text);
    } catch {
      return null;
    }
  } catch {
    return null;
  }
}

function resolveCurrency({ requestedCurrency, mkReqRes, profileRes }) {
  const requested = normalizeCurrency(requestedCurrency);
  const fromProfile = extractCurrencyCandidates(profileRes);
  const fromMkReq = extractCurrencyCandidates(mkReqRes);
  const supported = fromProfile.length ? fromProfile : fromMkReq;

  if (!supported.length) return requested || DEFAULT_CURRENCY;
  if (requested && supported.includes(requested)) return requested;
  return supported[0];
}

function renderCheckoutPage(baseUrl) {
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Cardzone UAT Checkout</title>
  <style>
    body{font-family:Arial,sans-serif;background:#f4f6f8;margin:0;padding:24px;color:#1f2937}
    .wrap{max-width:820px;margin:0 auto}
    .card{background:white;border-radius:16px;box-shadow:0 10px 30px rgba(0,0,0,.08);padding:24px}
    h1{margin:0 0 8px;font-size:28px}
    p.muted{color:#6b7280;margin:0 0 20px}
    .grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
    label{display:block;font-size:13px;font-weight:700;margin-bottom:6px}
    input,select{width:100%;padding:12px;border:1px solid #d1d5db;border-radius:10px;box-sizing:border-box}
    .full{grid-column:1 / -1}
    button{background:#111827;color:white;border:0;padding:12px 18px;border-radius:10px;font-weight:700;cursor:pointer}
    .note{margin-top:16px;padding:12px 14px;background:#fff7ed;border:1px solid #fdba74;border-radius:12px;font-size:14px}
    code{background:#f3f4f6;padding:2px 6px;border-radius:6px}
    @media (max-width:700px){.grid{grid-template-columns:1fr}}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>Cardzone UAT Checkout</h1>
      <p class="muted">Vercel-ready hosted payment starter.</p>
      <form method="post" action="/start-payment">
        <div class="grid">
          <div><label>Merchant ID</label><input name="merchantId" value="${escapeHtml(MERCHANT_ID)}" required /></div>
          <div><label>Currency (ISO 4217 numeric)</label><input name="currency" value="${escapeHtml(DEFAULT_CURRENCY)}" required /><small style="color:#6b7280">If Cardzone profile API is configured, this will be auto-resolved.</small></div>
          <div><label>Amount</label><input name="amount" value="1.00" required /></div>
          <div><label>Order / Purchase ID</label><input name="purchaseId" placeholder="Leave blank to auto-generate" /></div>
          <div><label>Order Reference</label><input name="orderRef" placeholder="Optional merchant order reference" /></div>
          <div><label>Customer Reference</label><input name="customerRef" placeholder="Optional customer/account reference" /></div>
          <div><label>Email</label><input name="email" type="email" value="uat@example.com" /></div>
          <div><label>Mobile phone</label><input name="mobilePhone" value="17123456" /></div>
          <div><label>Mobile phone country code</label><input name="mobilePhoneCc" value="1" /></div>
          <div><label>Billing country (ISO 3166-1 numeric)</label><input name="billCountry" value="840" /></div>
          <div><label>Billing city</label><input name="billCity" value="New York" /></div>
          <div><label>Billing postcode</label><input name="billPostcode" value="10001" /></div>
          <div class="full"><label>Billing address line 1</label><input name="billLine1" value="123 Main Street" /></div>
          <div>
            <label>Response type</label>
            <select name="responseType">
              <option value="STRING" ${RESPONSE_TYPE === 'STRING' ? 'selected' : ''}>STRING</option>
              <option value="JSON" ${RESPONSE_TYPE === 'JSON' ? 'selected' : ''}>JSON</option>
              <option value="">Default</option>
            </select>
          </div>
          <div><label>Response link</label><input name="responseLink" value="${escapeHtml(baseUrl + '/return?txnId=')}" /></div>
        </div>
        <div style="margin-top:20px"><button type="submit">Start UAT Payment</button></div>
      </form>
      <div class="note">Callback URL used: <code>${escapeHtml(baseUrl + '/callback')}</code></div>
    </div>
  </div>
</body>
</html>`;
}

function renderAutoPostPage(action, fields) {
  const inputs = Object.entries(fields)
    .filter(([, v]) => v !== undefined && v !== null)
    .map(([k, v]) => `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}">`)
    .join('\n');

  return `<!doctype html>
<html><head><meta charset="utf-8"><title>Redirecting...</title></head>
<body style="font-family:Arial,sans-serif;padding:24px">
  <p>Redirecting to Cardzone hosted payment page...</p>
  <form id="payForm" method="post" action="${escapeHtml(action)}">${inputs}</form>
  <script>document.getElementById('payForm').submit();</script>
</body></html>`;
}

function renderReturnPage(title, data) {
  const pretty = escapeHtml(JSON.stringify(data, null, 2));
  return `<!doctype html>
<html><head><meta charset="utf-8" /><title>${escapeHtml(title)}</title>
<style>body{font-family:Arial,sans-serif;background:#f5f7fb;padding:24px}.card{max-width:900px;margin:0 auto;background:#fff;padding:24px;border-radius:16px;box-shadow:0 10px 30px rgba(0,0,0,.08)}pre{background:#111827;color:#e5e7eb;padding:16px;border-radius:12px;overflow:auto}</style>
</head><body><div class="card"><h1>${escapeHtml(title)}</h1><pre>${pretty}</pre><a href="/">Back to checkout</a></div></body></html>`;
}

async function handleStartPayment(req, res) {
  const raw = await parseBody(req);
  const form = parseForm(raw);
  const requestBaseUrl = getRequestBaseUrl(req);

  const purchaseId = (form.purchaseId || generateTxnId()).trim();
  const merchantId = (form.merchantId || MERCHANT_ID).trim();
  const orderRef = (form.orderRef || purchaseId).trim();
  const customerRef = (form.customerRef || '').trim();
  const txnId = purchaseId;
  const purchDate = formatPurchDate(new Date());
  const amountMinor = amountToMinorUnits(form.amount || '1');

  if (!txnId) {
    return html(res, 400, renderReturnPage('Invalid request', { error: 'Transaction ID is required' }));
  }
  if (txStore.has(txnId)) {
    return html(res, 409, renderReturnPage('Duplicate transaction ID', {
      error: 'Duplicate MPI_TRXN_ID. Use a new transaction/order ID.',
      txnId,
    }));
  }

  const keys = createRsaKeyPair();
  const mkReqRes = await doMkReq({
    merchantId,
    purchaseId,
    merchantPublicKeyBase64Url: keys.publicKeyBase64Url,
    merchantPrivateKeyPem: keys.privateKeyPem,
  });

  const profileRes = await fetchCardzoneMerchantProfile(merchantId);
  const resolvedCurrency = resolveCurrency({
    requestedCurrency: (form.currency || DEFAULT_CURRENCY).trim(),
    mkReqRes,
    profileRes,
  });

  if (mkReqRes.errorCode !== '000' || !mkReqRes.pubKey) {
    return html(res, 400, renderReturnPage('mkReq failed', mkReqRes));
  }

  const tx = {
    merchantId,
    orderRef,
    customerRef,
    purchaseId,
    txnId,
    purchDate,
    amountMinor,
    currency: resolvedCurrency,
    email: (form.email || '').trim(),
    mobilePhone: (form.mobilePhone || '').trim(),
    mobilePhoneCc: (form.mobilePhoneCc || '').trim(),
    billCountry: (form.billCountry || '').trim(),
    billCity: (form.billCity || '').trim(),
    billPostcode: (form.billPostcode || '').trim(),
    billLine1: (form.billLine1 || '').trim(),
    responseType: form.responseType || RESPONSE_TYPE,
    responseLink: (form.responseLink || `${requestBaseUrl}/return?txnId=${txnId}`).trim(),
    merchantPrivateKeyPem: keys.privateKeyPem,
    cardzonePublicKeyBase64Url: mkReqRes.pubKey,
    mkReqRes,
    profileRes,
    currencySource: profileRes ? 'cardzone-profile' : 'request-or-mkReq',
    status: 'REQUEST_PREPARED',
    createdAt: new Date().toISOString(),
  };

  const mpiReq = {
    MPI_TRANS_TYPE: 'SALES',
    MPI_MERC_ID: tx.merchantId,
    MPI_TRXN_ID: tx.txnId,
    MPI_PURCH_DATE: tx.purchDate,
    MPI_PURCH_CURR: tx.currency,
    MPI_PURCH_AMT: tx.amountMinor,
    MPI_EMAIL: tx.email,
    MPI_MOBILE_PHONE: tx.mobilePhone,
    MPI_MOBILE_PHONE_CC: tx.mobilePhoneCc,
    MPI_BILL_ADDR_CNTRY: tx.billCountry,
    MPI_BILL_ADDR_CITY: tx.billCity,
    MPI_BILL_ADDR_POSTCODE: tx.billPostcode,
    MPI_BILL_ADDR_LINE1: tx.billLine1,
    MPI_RESPONSE_TYPE: tx.responseType,
    MPI_RESPONSE_LINK: tx.responseLink,
  };

  const macVariant = MPIREQ_INCLUDE_RESPONSE_LINK_IN_MAC
    ? 'spec+MPI_RESPONSE_LINK'
    : 'spec';
  const mpiReqSignInput = mpiReqSignString(mpiReq, {
    includeResponseLink: MPIREQ_INCLUDE_RESPONSE_LINK_IN_MAC,
  });
  const generatedMpiMac = signSha256WithRsaBase64Url(mpiReqSignInput, tx.merchantPrivateKeyPem);
  mpiReq.MPI_MAC = generatedMpiMac;

  console.log('[Cardzone][mercReq] endpoint=', CARDZONE_REDIRECT_URL);
  console.log('[Cardzone][mercReq] flow=hosted-page html-form-post=true');
  console.log('[Cardzone][signing] MAC variant=', macVariant);
  console.log('[Cardzone][signing] MPIReq fields used for signing:', JSON.stringify({
    MPI_TRANS_TYPE: mpiReq.MPI_TRANS_TYPE || '',
    MPI_MERC_ID: mpiReq.MPI_MERC_ID || '',
    MPI_PAN: mpiReq.MPI_PAN || '',
    MPI_CARD_HOLDER_NAME: mpiReq.MPI_CARD_HOLDER_NAME || '',
    MPI_PAN_EXP: mpiReq.MPI_PAN_EXP || '',
    MPI_CVV2: mpiReq.MPI_CVV2 || '',
    MPI_TRXN_ID: mpiReq.MPI_TRXN_ID || '',
    MPI_ORI_TRXN_ID: mpiReq.MPI_ORI_TRXN_ID || '',
    MPI_PURCH_DATE: mpiReq.MPI_PURCH_DATE || '',
    MPI_PURCH_CURR: mpiReq.MPI_PURCH_CURR || '',
    MPI_PURCH_AMT: mpiReq.MPI_PURCH_AMT || '',
    MPI_ADDR_MATCH: mpiReq.MPI_ADDR_MATCH || '',
    MPI_BILL_ADDR_CITY: mpiReq.MPI_BILL_ADDR_CITY || '',
    MPI_BILL_ADDR_STATE: mpiReq.MPI_BILL_ADDR_STATE || '',
    MPI_BILL_ADDR_CNTRY: mpiReq.MPI_BILL_ADDR_CNTRY || '',
    MPI_BILL_ADDR_POSTCODE: mpiReq.MPI_BILL_ADDR_POSTCODE || '',
    MPI_BILL_ADDR_LINE1: mpiReq.MPI_BILL_ADDR_LINE1 || '',
    MPI_BILL_ADDR_LINE2: mpiReq.MPI_BILL_ADDR_LINE2 || '',
    MPI_BILL_ADDR_LINE3: mpiReq.MPI_BILL_ADDR_LINE3 || '',
    MPI_SHIP_ADDR_CITY: mpiReq.MPI_SHIP_ADDR_CITY || '',
    MPI_SHIP_ADDR_STATE: mpiReq.MPI_SHIP_ADDR_STATE || '',
    MPI_SHIP_ADDR_CNTRY: mpiReq.MPI_SHIP_ADDR_CNTRY || '',
    MPI_SHIP_ADDR_POSTCODE: mpiReq.MPI_SHIP_ADDR_POSTCODE || '',
    MPI_SHIP_ADDR_LINE1: mpiReq.MPI_SHIP_ADDR_LINE1 || '',
    MPI_SHIP_ADDR_LINE2: mpiReq.MPI_SHIP_ADDR_LINE2 || '',
    MPI_SHIP_ADDR_LINE3: mpiReq.MPI_SHIP_ADDR_LINE3 || '',
    MPI_EMAIL: mpiReq.MPI_EMAIL || '',
    MPI_HOME_PHONE: mpiReq.MPI_HOME_PHONE || '',
    MPI_HOME_PHONE_CC: mpiReq.MPI_HOME_PHONE_CC || '',
    MPI_WORK_PHONE: mpiReq.MPI_WORK_PHONE || '',
    MPI_WORK_PHONE_CC: mpiReq.MPI_WORK_PHONE_CC || '',
    MPI_MOBILE_PHONE: mpiReq.MPI_MOBILE_PHONE || '',
    MPI_MOBILE_PHONE_CC: mpiReq.MPI_MOBILE_PHONE_CC || '',
    MPI_LINE_ITEM: Array.isArray(mpiReq.MPI_LINE_ITEM) ? mpiReq.MPI_LINE_ITEM : [],
    MPI_RESPONSE_TYPE: mpiReq.MPI_RESPONSE_TYPE || '',
    MPI_RESPONSE_LINK: mpiReq.MPI_RESPONSE_LINK || '',
    includeResponseLinkInMac: MPIREQ_INCLUDE_RESPONSE_LINK_IN_MAC,
  }));
  console.log('[Cardzone][signing] Pre-sign concatenated string:', mpiReqSignInput);
  console.log('[Cardzone][signing] Generated MPI_MAC (base64url, no padding):', generatedMpiMac);

  tx.requestFields = mpiReq;
  tx.status = 'REDIRECTED_TO_HOSTED_PAGE';
  txStore.set(tx.txnId, tx);

  // Persist to file for Vercel
  try {
    await fs.mkdir(TEMP_DIR, { recursive: true });
    const txFile = path.join(TEMP_DIR, `txn_${txnId}.json`);
    await fs.writeFile(txFile, JSON.stringify(tx, null, 2), 'utf8');
  } catch (e) {
    console.error(`Failed to persist transaction to file: ${e.message}`);
  }

  html(res, 200, renderAutoPostPage(CARDZONE_REDIRECT_URL, mpiReq));
}

async function handleCallback(req, res) {
  const raw = await parseBody(req);
  const contentType = (req.headers['content-type'] || '').toLowerCase();
  let fields = {};
  if (contentType.includes('application/json')) {
    try {
      fields = JSON.parse(raw || '{}');
    } catch {
      fields = {};
    }
  } else {
    fields = parseForm(raw);
  }

  const txnId = fields.MPI_TRXN_ID || fields.mpiTrxnId || fields.trxnId || '';
  let tx = txStore.get(txnId);

  // If not in memory, try to load from file
  if (!tx && txnId) {
    try {
      const txFile = path.join(TEMP_DIR, `txn_${txnId}.json`);
      const content = await fs.readFile(txFile, 'utf8');
      tx = JSON.parse(content);
    } catch (e) {
      // File not found or parse error
    }
  }

  let macVerified = false;
  let verifyNote = 'Skipped: original transaction not found in local memory';
  let orderStatus = 'PENDING';

  if (tx && fields.MPI_MAC) {
    const verifyString = mpiResVerifyString(fields);
    macVerified = verifySha256WithRsaBase64Url(verifyString, fields.MPI_MAC, tx.cardzonePublicKeyBase64Url);
    verifyNote = macVerified ? 'MPIRes MAC verified successfully' : 'MPIRes MAC verification failed';
  }

  orderStatus = mapTransactionStatus({
    callbackReceived: true,
    hasMac: !!fields.MPI_MAC,
    macVerified,
    errorCode: fields.MPI_ERROR_CODE,
    approvalCode: fields.MPI_APPR_CODE,
  });

  const result = {
    receivedAt: new Date().toISOString(),
    method: req.method,
    contentType,
    macVerified,
    verifyNote,
    orderStatus,
    rawPayload: raw,
    fields,
  };

  if (tx) {
    tx.callback = result;
    tx.status = orderStatus;
    txStore.set(tx.txnId, tx);

    // Persist updated transaction to file
    try {
      const txFile = path.join(TEMP_DIR, `txn_${txnId}.json`);
      await fs.writeFile(txFile, JSON.stringify(tx, null, 2), 'utf8');
    } catch (e) {
      console.error(`Failed to update transaction file: ${e.message}`);
    }
  }

  html(res, 200, renderReturnPage('Cardzone callback received', result));
}

async function handleReturn(req, res) {
  const u = new URL(req.url, `http://${req.headers.host}`);
  
  // Extract txnId from query params (works for both GET and POST)
  let txnId = u.searchParams.get('txnId');
  
  // For POST requests, also check the request body for MPI fields
  let mpiFields = {};
  let rawReturnPayload = '';
  if (req.method === 'POST') {
    rawReturnPayload = await parseBody(req);
    const contentType = (req.headers['content-type'] || '').toLowerCase();
    
    if (contentType.includes('application/json')) {
      try {
        mpiFields = JSON.parse(rawReturnPayload || '{}');
      } catch (e) {
        mpiFields = {};
      }
    } else {
      mpiFields = parseForm(rawReturnPayload);
    }
    
    // Extract txnId from POST body if not in query params
    if (!txnId) {
      txnId = mpiFields.MPI_TRXN_ID || mpiFields.txnId || '';
    }
  }

  if (!txnId) {
    return html(res, 400, renderReturnPage('No transaction reference received', {
      error: 'No transaction reference received',
      note: 'The transaction reference must be provided via query parameter (txnId) or POST field (MPI_TRXN_ID).',
    }));
  }

  let tx = txStore.get(txnId);

  // If not in memory, try to load from file
  if (!tx) {
    try {
      const txFile = path.join(TEMP_DIR, `txn_${txnId}.json`);
      const content = await fs.readFile(txFile, 'utf8');
      tx = JSON.parse(content);
    } catch (e) {
      // File not found or parse error
    }
  }

  if (!tx) {
    return html(res, 404, renderReturnPage('Transaction not found', {
      txnId,
      error: 'No transaction record found for this reference.',
      note: 'The transaction may have expired or the reference may be incorrect.',
    }));
  }

  // If this is a POST with MPI response fields, update the transaction
  if (req.method === 'POST' && Object.keys(mpiFields).length > 0) {
    let macVerified = false;
    let verifyNote = 'No MAC in response';
    let orderStatus = tx.status || 'PENDING';

    if (mpiFields.MPI_MAC && tx.cardzonePublicKeyBase64Url) {
      const verifyString = mpiResVerifyString(mpiFields);
      macVerified = verifySha256WithRsaBase64Url(
        verifyString,
        mpiFields.MPI_MAC,
        tx.cardzonePublicKeyBase64Url,
      );
      verifyNote = macVerified ? 'MPIRes MAC verified successfully' : 'MPIRes MAC verification failed';
    }

    orderStatus = mapTransactionStatus({
      callbackReceived: true,
      hasMac: !!mpiFields.MPI_MAC,
      macVerified,
      errorCode: mpiFields.MPI_ERROR_CODE,
      approvalCode: mpiFields.MPI_APPR_CODE,
    });

    // Update transaction with callback data
    tx.callback = {
      receivedAt: new Date().toISOString(),
      method: req.method,
      macVerified,
      verifyNote,
      orderStatus,
      rawPayload: rawReturnPayload,
      fields: mpiFields,
    };
    tx.status = orderStatus;
    txStore.set(tx.txnId, tx);

    // Persist updated transaction to file
    try {
      const txFile = path.join(TEMP_DIR, `txn_${txnId}.json`);
      await fs.writeFile(txFile, JSON.stringify(tx, null, 2), 'utf8');
    } catch (e) {
      console.error(`Failed to update transaction file: ${e.message}`);
    }
  }

  const callbackReceived = !!tx.callback;
  const mappedStatus = mapTransactionStatus({
    callbackReceived,
    hasMac: !!tx.callback?.fields?.MPI_MAC,
    macVerified: !!tx.callback?.macVerified,
    errorCode: tx.callback?.fields?.MPI_ERROR_CODE,
    approvalCode: tx.callback?.fields?.MPI_APPR_CODE,
  });

  tx.status = mappedStatus;

  const displayData = {
    txnId: tx.txnId,
    orderRef: tx.orderRef,
    customerRef: tx.customerRef,
    merchantId: tx.merchantId,
    status: tx.status || 'PENDING',
    amountMinor: tx.amountMinor,
    currency: tx.currency,
    createdAt: tx.createdAt,
    callbackReceived,
    callbackData: tx.callback ? {
      receivedAt: tx.callback.receivedAt,
      orderStatus: tx.callback.orderStatus,
      macVerified: tx.callback.macVerified,
      verifyNote: tx.callback.verifyNote,
      rawPayload: tx.callback.rawPayload || null,
      mpiErrorCode: tx.callback.fields?.MPI_ERROR_CODE || null,
      mpiErrorDesc: tx.callback.fields?.MPI_ERROR_DESC || null,
      mpiApprCode: tx.callback.fields?.MPI_APPR_CODE || null,
      mpiRrn: tx.callback.fields?.MPI_RRN || null,
      mpiReferralCode: tx.callback.fields?.MPI_REFERRAL_CODE || null,
      mpiBin: tx.callback.fields?.MPI_BIN || null,
      allResponseFields: tx.callback.fields || {},
    } : null,
    note: 'Transaction details retrieved from persistent storage.',
  };

  html(res, 200, renderReturnPage(`Payment Result: ${tx.status || 'PENDING'}`, displayData));
}

function handleList(req, res) {
  const items = [...txStore.entries()].map(([k, v]) => ({
    txnId: k,
    orderRef: v.orderRef,
    customerRef: v.customerRef,
    merchantId: v.merchantId,
    amountMinor: v.amountMinor,
    currency: v.currency,
    status: v.status || null,
    createdAt: v.createdAt,
    callbackReceived: !!v.callback,
    mpiErrorCode: v.callback?.fields?.MPI_ERROR_CODE || null,
  }));
  json(res, 200, items);
}

module.exports = async function handler(req, res) {
  try {
    const u = new URL(req.url, `http://${req.headers.host}`);

    if (req.method === 'GET' && (u.pathname === '/favicon.ico' || u.pathname === '/favicon.png')) {
      res.statusCode = 204;
      res.setHeader('Cache-Control', 'public, max-age=86400');
      return res.end();
    }

    if (req.method === 'GET' && u.pathname === '/') {
      return html(res, 200, renderCheckoutPage(getRequestBaseUrl(req)));
    }
    if (req.method === 'POST' && u.pathname === '/start-payment') {
      return await handleStartPayment(req, res);
    }
    if (req.method === 'POST' && u.pathname === '/callback') {
      return await handleCallback(req, res);
    }
    if ((req.method === 'GET' || req.method === 'POST') && u.pathname === '/return') {
      return await handleReturn(req, res);
    }
    if (req.method === 'GET' && u.pathname === '/transactions') {
      return handleList(req, res);
    }

    html(res, 404, '<h1>Not Found</h1>');
  } catch (err) {
    html(res, 500, renderReturnPage('Server error', {
      error: err.message,
      stack: err.stack,
    }));
  }
};
