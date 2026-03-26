// Field-level encryption module for NGINX njs
// Direct AWS KMS + WebCrypto implementation — no kms-bridge dependency
// Requirements: 1.1, 1.2, 4.2, 5.5

import fs from 'fs';

// ---------------------------------------------------------------------------
// Minimal YAML parser — supports the subset used by config.yaml:
//   nested objects and lists of objects with key: value pairs
// ---------------------------------------------------------------------------
function parseSimpleYaml(content) {
    const lines = content.split('\n')
        .map(l => l.replace(/#.*$/, '').trimEnd());

    let idx = 0;

    function skipEmpty() {
        while (idx < lines.length && !lines[idx].trim()) idx++;
    }

    function indentOf(line) {
        return line.match(/^(\s*)/)[1].length;
    }

    function parseBlock() {
        skipEmpty();
        if (idx >= lines.length) return {};

        const baseIndent = indentOf(lines[idx]);

        if (lines[idx].trim().startsWith('- ')) {
            const arr = [];
            while (idx < lines.length) {
                skipEmpty();
                if (idx >= lines.length || indentOf(lines[idx]) < baseIndent) break;
                const trimmed = lines[idx].trim();
                if (!trimmed.startsWith('- ')) break;

                const itemContent = trimmed.slice(2).trim();
                const kv = itemContent.match(/^([\w]+):\s*(.*)$/);
                if (kv) {
                    const item = { [kv[1]]: kv[2] !== '' ? kv[2] : null };
                    idx++;
                    skipEmpty();
                    if (idx < lines.length && indentOf(lines[idx]) > baseIndent) {
                        Object.assign(item, parseBlock());
                    }
                    arr.push(item);
                } else {
                    arr.push(itemContent || true);
                    idx++;
                }
            }
            return arr;
        } else {
            const obj = {};
            while (idx < lines.length) {
                skipEmpty();
                if (idx >= lines.length || indentOf(lines[idx]) < baseIndent) break;
                const trimmed = lines[idx].trim();
                const kv = trimmed.match(/^([\w]+):\s*(.*)$/);
                if (kv) {
                    const k = kv[1], v = kv[2];
                    idx++;
                    if (v !== '') {
                        obj[k] = v;
                    } else {
                        skipEmpty();
                        if (idx < lines.length && indentOf(lines[idx]) > baseIndent) {
                            obj[k] = parseBlock();
                        } else {
                            obj[k] = {};
                        }
                    }
                } else {
                    idx++;
                }
            }
            return obj;
        }
    }

    return parseBlock();
}

// ---------------------------------------------------------------------------
// Config loading — runs once per worker at module import time
// Requirement 4.2: Load field selectors from configuration file
// ---------------------------------------------------------------------------
let config = null;

(function loadConfig() {
    let raw;
    try {
        raw = fs.readFileSync('/etc/nginx/config.yaml', 'utf8');
    } catch (e) {
        ngx.log(ngx.ERR, 'FATAL: Cannot read /etc/nginx/config.yaml: ' + e.message);
        return;
    }

    let cfg;
    try {
        cfg = parseSimpleYaml(raw);
    } catch (e) {
        ngx.log(ngx.ERR, 'FATAL: Failed to parse config.yaml: ' + e.message);
        return;
    }

    if (!cfg.kms || !cfg.kms.region || !cfg.kms.key_id) {
        ngx.log(ngx.ERR, 'FATAL: config.yaml missing kms.region or kms.key_id');
        return;
    }
    if (!cfg.encryption || !Array.isArray(cfg.encryption.fields) || cfg.encryption.fields.length === 0) {
        ngx.log(ngx.ERR, 'FATAL: config.yaml missing a non-empty encryption.fields list');
        return;
    }

    for (let i = 0; i < cfg.encryption.fields.length; i++) {
        const field = cfg.encryption.fields[i];
        if (!field || !field.path) {
            ngx.log(ngx.ERR, 'FATAL: field entry ' + (i + 1) + ' is missing the required path key');
            return;
        }
        const p = field.path;
        if (!/^\$\.[a-zA-Z_][a-zA-Z0-9_]*/.test(p) || p.includes('..') || p.includes('*') || p.includes('[')) {
            ngx.log(ngx.ERR, 'FATAL: invalid field path "' + p + '" — use $.field or $.parent.child');
            return;
        }
    }

    config = cfg;

    ngx.log(ngx.INFO, '==============================================');
    ngx.log(ngx.INFO, 'Field-Level Encryption Demo - NGINX njs Started');
    ngx.log(ngx.INFO, 'KMS: direct SigV4 + WebCrypto AES-256-GCM');
    ngx.log(ngx.INFO, '==============================================');
    ngx.log(ngx.INFO, 'KMS Region: ' + config.kms.region);
    ngx.log(ngx.INFO, 'KMS Key ID: ' + config.kms.key_id);
    ngx.log(ngx.INFO, 'Configured Fields: ' + config.encryption.fields.length);
    config.encryption.fields.forEach((f, i) => {
        ngx.log(ngx.INFO, '  ' + (i + 1) + '. ' + f.path + (f.description ? ' - ' + f.description : ''));
    });
    ngx.log(ngx.INFO, '==============================================');
})();

// ---------------------------------------------------------------------------
// JSONPath helpers — supports $.field and $.parent.child notation
// ---------------------------------------------------------------------------
function getFieldValue(obj, path) {
    const parts = path.replace(/^\$\./, '').split('.');
    let cur = obj;
    for (let i = 0; i < parts.length; i++) {
        if (cur == null || typeof cur !== 'object') return undefined;
        cur = cur[parts[i]];
    }
    return cur;
}

function setFieldValue(obj, path, value) {
    const parts = path.replace(/^\$\./, '').split('.');
    let cur = obj;
    for (let i = 0; i < parts.length - 1; i++) {
        if (typeof cur !== 'object') return false;
        if (cur[parts[i]] == null) cur[parts[i]] = {};
        cur = cur[parts[i]];
    }
    if (typeof cur === 'object') {
        cur[parts[parts.length - 1]] = value;
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Base64 helpers
// ---------------------------------------------------------------------------
function b64encode(bytes) {
    return Buffer.from(bytes).toString('base64');
}

function b64decode(str) {
    return new Uint8Array(Buffer.from(str, 'base64'));
}

// ---------------------------------------------------------------------------
// AWS SigV4 signing using WebCrypto (crypto.subtle)
// ---------------------------------------------------------------------------
function toHex(bytes) {
    return Array.from(new Uint8Array(bytes))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

async function sha256Hex(data) {
    const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    const hash  = await crypto.subtle.digest('SHA-256', bytes);
    return toHex(hash);
}

async function hmacSHA256(keyBytes, data) {
    const key = await crypto.subtle.importKey(
        'raw', keyBytes,
        { name: 'HMAC', hash: 'SHA-256' },
        false, ['sign']
    );
    const dataBytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    const sig = await crypto.subtle.sign('HMAC', key, dataBytes);
    return new Uint8Array(sig);
}

// ---------------------------------------------------------------------------
// Direct KMS API call via ngx.fetch with SigV4 signing
// ---------------------------------------------------------------------------
async function kmsRequest(target, bodyObj) {
    const region       = config.kms.region;
    const accessKey    = process.env.AWS_ACCESS_KEY_ID;
    const secretKey    = process.env.AWS_SECRET_ACCESS_KEY;
    const sessionToken = process.env.AWS_SESSION_TOKEN || null;
    const host         = 'kms.' + region + '.amazonaws.com';
    const endpoint     = 'https://' + host + '/';
    const body         = JSON.stringify(bodyObj);

    // Format date strings for SigV4
    const iso      = new Date().toISOString();
    const amzDate  = iso.slice(0,4) + iso.slice(5,7) + iso.slice(8,10) +
                     'T' + iso.slice(11,13) + iso.slice(14,16) + iso.slice(17,19) + 'Z';
    const dateStamp = amzDate.slice(0, 8);

    // Build canonical headers (must be sorted)
    const hdrs = {
        'content-type':  'application/x-amz-json-1.1',
        'host':           host,
        'x-amz-date':     amzDate,
        'x-amz-target':   target,
    };
    if (sessionToken) hdrs['x-amz-security-token'] = sessionToken;

    const sortedKeys       = Object.keys(hdrs).sort();
    const canonicalHeaders = sortedKeys.map(k => k + ':' + hdrs[k] + '\n').join('');
    const signedHeaders    = sortedKeys.join(';');
    const payloadHash      = await sha256Hex(body);

    const canonicalRequest = ['POST', '/', '', canonicalHeaders, signedHeaders, payloadHash].join('\n');
    const scope            = dateStamp + '/' + region + '/kms/aws4_request';
    const canonicalHash    = await sha256Hex(canonicalRequest);
    const stringToSign     = ['AWS4-HMAC-SHA256', amzDate, scope, canonicalHash].join('\n');

    // Derive signing key: HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), service), "aws4_request")
    const kDate    = await hmacSHA256(new TextEncoder().encode('AWS4' + secretKey), dateStamp);
    const kRegion  = await hmacSHA256(kDate, region);
    const kService = await hmacSHA256(kRegion, 'kms');
    const kSigning = await hmacSHA256(kService, 'aws4_request');
    const sigBytes  = await hmacSHA256(kSigning, stringToSign);
    const signature = toHex(sigBytes);

    hdrs['authorization'] = 'AWS4-HMAC-SHA256 Credential=' + accessKey + '/' + scope +
        ', SignedHeaders=' + signedHeaders + ', Signature=' + signature;

    let res;
    try {
        res = await ngx.fetch(endpoint, { method: 'POST', headers: hdrs, body, timeout: 5000 });
    } catch (e) {
        throw new Error('KMS network error: ' + e.message);
    }

    if (res.status !== 200) {
        let errMsg = 'KMS error (HTTP ' + res.status + ')';
        try {
            const err = await res.json();
            errMsg = err.Message || err.message || errMsg;
        } catch (_) {}
        throw new Error(errMsg);
    }

    return res.json();
}

// ---------------------------------------------------------------------------
// Envelope encrypt — KMS GenerateDataKey + AES-256-GCM (WebCrypto)
// ---------------------------------------------------------------------------
async function envelopeEncrypt(plaintext) {
    const t0 = Date.now();

    // 1. Request ephemeral DEK from KMS
    const kmsData  = await kmsRequest('TrentService.GenerateDataKey', {
        KeyId: config.kms.key_id, KeySpec: 'AES_256',
    });
    const dekBytes = b64decode(kmsData.Plaintext);  // raw DEK — discard after use
    const edk      = kmsData.CiphertextBlob;         // encrypted DEK — safe to store
    const cmkId    = kmsData.KeyId;

    // 2. AES-256-GCM encrypt locally
    const aesKey = await crypto.subtle.importKey('raw', dekBytes, 'AES-GCM', false, ['encrypt']);
    const iv     = crypto.getRandomValues(new Uint8Array(12));
    const ctBuf  = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(plaintext)
    );
    const ct     = new Uint8Array(ctBuf);

    // 3. Zero DEK (best-effort in JS)
    dekBytes.fill(0);

    // 4. Pack self-contained envelope: version + EDK + IV + ciphertext
    const envelope   = JSON.stringify({ v: 1, edk, iv: b64encode(iv), ct: b64encode(ct) });
    const ciphertext = 'ENC_V1_' + b64encode(new TextEncoder().encode(envelope));

    return { ciphertext, cmkId, durationMs: Date.now() - t0 };
}

// ---------------------------------------------------------------------------
// Envelope decrypt — KMS Decrypt(EDK) + AES-256-GCM (WebCrypto)
// ---------------------------------------------------------------------------
async function envelopeDecrypt(ciphertext) {
    const t0 = Date.now();

    if (!ciphertext.startsWith('ENC_V1_')) {
        throw new Error('Unknown ciphertext format - expected ENC_V1_ prefix');
    }

    let envelope;
    try {
        envelope = JSON.parse(new TextDecoder().decode(b64decode(ciphertext.slice(7))));
    } catch (e) {
        throw new Error('Malformed envelope: ' + e.message);
    }

    const edk   = envelope.edk;
    const ivB64 = envelope.iv;
    const ctB64 = envelope.ct;

    // 1. Recover DEK via KMS Decrypt
    const kmsData  = await kmsRequest('TrentService.Decrypt', { CiphertextBlob: edk });
    const dekBytes = b64decode(kmsData.Plaintext);
    const cmkId    = kmsData.KeyId;

    // 2. AES-256-GCM decrypt locally
    const aesKey    = await crypto.subtle.importKey('raw', dekBytes, 'AES-GCM', false, ['decrypt']);
    const plainBuf  = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: b64decode(ivB64) }, aesKey, b64decode(ctB64)
    );
    const plaintext = new TextDecoder().decode(plainBuf);

    // 3. Zero DEK
    dekBytes.fill(0);

    return { plaintext, cmkId, durationMs: Date.now() - t0 };
}

// ---------------------------------------------------------------------------
// Content handler: /api/ — encrypt request fields, proxy to backend
// Requirements: 1.1 (encrypt)
// ---------------------------------------------------------------------------
async function proxyAndEncrypt(r) {
    if (!config) {
        r.headersOut['Content-Type'] = 'application/json';
        r.return(500, JSON.stringify({ error: 'Configuration not loaded' }));
        return;
    }

    const method = r.method;
    const contentType = r.headersIn['Content-Type'] || '';
    let body = r.requestText;
    let encryptMetrics = null;
    let encryptedPayload = null;

    if ((method === 'POST' || method === 'PUT') &&
        contentType.includes('application/json') && body) {

        ngx.log(ngx.INFO, 'Processing request for encryption...');

        let data;
        try {
            data = JSON.parse(body);
        } catch (e) {
            r.headersOut['Content-Type'] = 'application/json';
            r.return(400, JSON.stringify({ error: 'Invalid JSON body' }));
            return;
        }

        const fieldsEncrypted = [];
        let totalEncryptMs = 0;
        let lastResult = null;

        for (let fi = 0; fi < config.encryption.fields.length; fi++) {
            const fieldCfg  = config.encryption.fields[fi];
            const fieldPath = fieldCfg.path;
            const fieldValue = getFieldValue(data, fieldPath);

            if (fieldValue != null && fieldValue !== '') {
                let result;
                try {
                    result = await envelopeEncrypt(String(fieldValue));
                } catch (e) {
                    ngx.log(ngx.ERR, 'Encryption failed for ' + fieldPath + ': ' + e.message);
                    r.headersOut['Content-Type'] = 'application/json';
                    r.return(500, JSON.stringify({ error: 'Encryption failed', detail: e.message }));
                    return;
                }

                setFieldValue(data, fieldPath, result.ciphertext);
                ngx.log(ngx.INFO, '[ENCRYPTED] field=' + fieldPath +
                    ', kms_key=' + result.cmkId +
                    ', duration=' + result.durationMs + 'ms' +
                    ', value=' + result.ciphertext.substring(0, 50) + '...');

                fieldsEncrypted.push(fieldPath);
                totalEncryptMs += result.durationMs || 0;
                lastResult = result;
            }
        }

        if (fieldsEncrypted.length === 0) {
            ngx.log(ngx.INFO, 'No sensitive fields found in request, passing through');
        } else {
            ngx.log(ngx.INFO, 'Encrypted ' + fieldsEncrypted.length + ' fields in ' + totalEncryptMs + 'ms');
        }

        body = JSON.stringify(data);
        encryptedPayload = data;
        encryptMetrics = {
            encrypt_time_ms:  totalEncryptMs,
            fields_encrypted: fieldsEncrypted,
            kms_endpoint:     'https://kms.' + config.kms.region + '.amazonaws.com/',
            kms_region:       config.kms.region,
            kms_key_id:       (lastResult && lastResult.cmkId) || config.kms.key_id,
            data_key_id:      null,
        };
    }

    // Proxy to backend
    const backendUrl = 'http://backend:5000' + r.variables.request_uri;
    const fetchHeaders = {
        'Host':       'backend',
        'X-Real-IP':  r.variables.remote_addr,
    };
    if (method === 'POST' || method === 'PUT') {
        fetchHeaders['Content-Type'] = 'application/json';
    }

    let backendRes;
    try {
        backendRes = await ngx.fetch(backendUrl, {
            method,
            headers: fetchHeaders,
            body: body || undefined,
            timeout: 10000,
        });
    } catch (e) {
        ngx.log(ngx.ERR, 'Backend request failed: ' + e.message);
        r.headersOut['Content-Type'] = 'application/json';
        r.return(502, JSON.stringify({ error: 'Backend unavailable', detail: e.message }));
        return;
    }

    const backendBody = await backendRes.text();

    if (encryptMetrics && encryptMetrics.fields_encrypted.length > 0) {
        let backendData;
        try { backendData = JSON.parse(backendBody); } catch (_) { backendData = null; }

        if (backendData !== null && typeof backendData === 'object') {
            const response = {
                encrypted_payload: encryptedPayload || {},
                backend_response:  backendData,
                metrics: {
                    kms_endpoint:     encryptMetrics.kms_endpoint,
                    kms_region:       encryptMetrics.kms_region,
                    kms_key_id:       encryptMetrics.kms_key_id,
                    data_key_id:      encryptMetrics.data_key_id,
                    encrypt_time_ms:  encryptMetrics.encrypt_time_ms || 0,
                    decrypt_time_ms:  0,
                    fields_encrypted: encryptMetrics.fields_encrypted || [],
                },
            };
            r.headersOut['Content-Type'] = 'application/json';
            r.return(backendRes.status, JSON.stringify(response));
            return;
        }
    }

    backendRes.headers.forEach((name, value) => {
        const lower = name.toLowerCase();
        if (lower !== 'transfer-encoding' && lower !== 'connection') {
            r.headersOut[name] = value;
        }
    });
    r.return(backendRes.status, backendBody);
}

// ---------------------------------------------------------------------------
// Content handler: /api/decrypt — decrypt ciphertext fields and return plaintext
// Requirement 1.2 (decrypt)
// ---------------------------------------------------------------------------
async function decryptHandler(r) {
    if (!config) {
        r.headersOut['Content-Type'] = 'application/json';
        r.return(500, JSON.stringify({ error: 'Configuration not loaded' }));
        return;
    }

    const body = r.requestText;
    if (!body) {
        r.headersOut['Content-Type'] = 'application/json';
        r.return(400, JSON.stringify({ error: 'No body' }));
        return;
    }

    let data;
    try {
        data = JSON.parse(body);
    } catch (e) {
        r.headersOut['Content-Type'] = 'application/json';
        r.return(400, JSON.stringify({ error: 'Invalid JSON' }));
        return;
    }

    const decrypted = {};
    let totalMs = 0;
    let lastCmkId = null;

    const keys = Object.keys(data);
    for (let ki = 0; ki < keys.length; ki++) {
        const k = keys[ki], v = data[k];
        if (typeof v === 'string' && v.startsWith('ENC_V1_')) {
            try {
                const result = await envelopeDecrypt(v);
                decrypted[k]  = result.plaintext;
                totalMs      += result.durationMs || 0;
                lastCmkId     = result.cmkId;
            } catch (e) {
                ngx.log(ngx.ERR, 'Decrypt failed for field ' + k + ': ' + e.message);
                decrypted[k] = v; // preserve ciphertext on error
            }
        } else {
            decrypted[k] = v;
        }
    }

    r.headersOut['Content-Type'] = 'application/json';
    r.return(200, JSON.stringify({
        decrypted_payload: decrypted,
        metrics: {
            kms_endpoint:    'https://kms.' + config.kms.region + '.amazonaws.com/',
            kms_region:      config.kms.region,
            kms_key_id:      lastCmkId || config.kms.key_id,
            data_key_id:     null,
            decrypt_time_ms: totalMs,
        },
    }));
}

// ---------------------------------------------------------------------------
// Content handler: /api/flush-cache — no-op (no cache with direct KMS)
// ---------------------------------------------------------------------------
async function flushCacheHandler(r) {
    r.headersOut['Content-Type'] = 'application/json';
    r.return(200, JSON.stringify({ status: 'flushed', message: 'Key cache cleared' }));
}

export default { proxyAndEncrypt, decryptHandler, flushCacheHandler };
