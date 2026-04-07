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
const DEFAULT_CURRENCY = '840';
const ENABLE_MKREQ_MAC = process.env.ENABLE_MKREQ_MAC === 'true';
const TEMP_DIR = process.env.VERCEL ? '/tmp' : path.join(os.tmpdir(), 'cardzone-backend');

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
  const orderRef = String(input.orderRef || '').trim();
  const customerRef = String(input.customerRef || '').trim();
  const customerName = String(input.customerName || '').trim();
  const email = String(input.email || '').trim();
  const mobilePhone = String(input.mobilePhone || '').trim();
  const successReturnUrl = String(input.successReturnUrl || '').trim();
  const failReturnUrl = String(input.failReturnUrl || '').trim();
  const txnId = String(input.txnId || generateTxnId()).trim();

  const missing = [];
  if (!merchantId) missing.push('merchantId');
  if (!amount) missing.push('amount');
  if (!orderRef) missing.push('orderRef');
  if (!customerRef) missing.push('customerRef');
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
    MPI_PURCH_CURR: DEFAULT_CURRENCY,
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
    currency: DEFAULT_CURRENCY,
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

    if (req.method === 'GET' && (u.pathname === '/' || u.pathname === '/api')) {
      return html(res, 200, renderDeveloperHome(getRequestBaseUrl(req)));
    }

    if (req.method === 'POST' && (u.pathname === '/api/initiate' || u.pathname === '/initiate')) {
      return await handleInitiate(req, res);
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
