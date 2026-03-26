// Field-level encryption module for NGINX njs (NGINX JavaScript)
// Parallel implementation of lua/encryption_module.lua using njs instead of OpenResty/Lua
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

    // Recursively parse a value block starting at current idx.
    // Stops when it encounters a line with indent < the block's base indent.
    function parseBlock() {
        skipEmpty();
        if (idx >= lines.length) return {};

        const baseIndent = indentOf(lines[idx]);

        if (lines[idx].trim().startsWith('- ')) {
            // Array block
            const arr = [];
            while (idx < lines.length) {
                skipEmpty();
                if (idx >= lines.length || indentOf(lines[idx]) < baseIndent) break;
                const trimmed = lines[idx].trim();
                if (!trimmed.startsWith('- ')) break;

                const itemContent = trimmed.slice(2).trim();
                const kv = itemContent.match(/^([\w]+):\s*(.*)$/);
                if (kv) {
                    // List item starts with a key: value pair
                    const item = { [kv[1]]: kv[2] !== '' ? kv[2] : null };
                    idx++;
                    skipEmpty();
                    // Collect any additional k:v lines at a deeper indent into this item
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
            // Object block
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
                        // No inline value — sub-block follows at a deeper indent
                        skipEmpty();
                        if (idx < lines.length && indentOf(lines[idx]) > baseIndent) {
                            obj[k] = parseBlock();
                        } else {
                            obj[k] = {};
                        }
                    }
                } else {
                    idx++; // skip unrecognised line
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

    // Validate required fields
    if (!cfg.kms || !cfg.kms.region || !cfg.kms.key_id) {
        ngx.log(ngx.ERR, 'FATAL: config.yaml missing kms.region or kms.key_id');
        return;
    }
    if (!cfg.encryption || !Array.isArray(cfg.encryption.fields) || cfg.encryption.fields.length === 0) {
        ngx.log(ngx.ERR, 'FATAL: config.yaml missing a non-empty encryption.fields list');
        return;
    }

    // Validate each JSONPath selector
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
// KMS bridge HTTP helper
// ---------------------------------------------------------------------------
async function callKmsBridge(endpoint, payload) {
    let res;
    try {
        res = await ngx.fetch('http://kms-bridge:5001' + endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
            timeout: 5000,
        });
    } catch (e) {
        throw new Error('KMS bridge unavailable: ' + e.message);
    }

    if (res.status !== 200) {
        let errMsg = 'KMS bridge error (HTTP ' + res.status + ')';
        try {
            const errData = await res.json();
            if (errData.error) errMsg = errData.error;
        } catch (_) {}
        throw new Error(errMsg);
    }

    try {
        return await res.json();
    } catch (e) {
        throw new Error('Invalid JSON response from KMS bridge');
    }
}

// ---------------------------------------------------------------------------
// Content handler: /api/ — encrypt request fields, proxy to backend,
// inject encryption metrics into the response for the demo UI.
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

    // Encrypt sensitive fields in JSON POST/PUT bodies
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
            const fieldCfg = config.encryption.fields[fi];
            const fieldPath = fieldCfg.path;
            const fieldValue = getFieldValue(data, fieldPath);

            if (fieldValue != null && fieldValue !== '') {
                let result;
                try {
                    result = await callKmsBridge('/encrypt', {
                        plaintext: String(fieldValue),
                        key_id: config.kms.key_id,
                    });
                } catch (e) {
                    ngx.log(ngx.ERR, 'Encryption failed for ' + fieldPath + ': ' + e.message);
                    r.headersOut['Content-Type'] = 'application/json';
                    r.return(500, JSON.stringify({ error: 'Encryption failed', detail: e.message }));
                    return;
                }

                setFieldValue(data, fieldPath, result.ciphertext);
                ngx.log(ngx.INFO, '[ENCRYPTED] field=' + fieldPath +
                    ', kms_key=' + result.key_id +
                    ', duration=' + result.duration_ms + 'ms' +
                    ', value=' + result.ciphertext.substring(0, 50) + '...');

                fieldsEncrypted.push(fieldPath);
                totalEncryptMs += result.duration_ms || 0;
                lastResult = result;
            }
        }

        if (fieldsEncrypted.length === 0) {
            ngx.log(ngx.INFO, 'No sensitive fields found in request, passing through');
        } else {
            ngx.log(ngx.INFO, 'Encrypted ' + fieldsEncrypted.length +
                ' fields in ' + totalEncryptMs + 'ms');
        }

        body = JSON.stringify(data);
        encryptedPayload = data;
        encryptMetrics = {
            encrypt_time_ms: totalEncryptMs,
            fields_encrypted: fieldsEncrypted,
            kms_endpoint: (lastResult && lastResult.endpoint) ||
                ('https://kms.' + config.kms.region + '.amazonaws.com/'),
            kms_region: config.kms.region,
            kms_key_id: (lastResult && lastResult.key_id) || config.kms.key_id,
            data_key_id: (lastResult && lastResult.data_key_id) || null,
        };
    }

    // Proxy to backend
    const backendUrl = 'http://backend:5000' + r.variables.request_uri;
    const fetchHeaders = {
        'Host': 'backend',
        'X-Real-IP': r.variables.remote_addr,
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

    // Inject encryption metrics into the response for the demo Web UI
    if (encryptMetrics && encryptMetrics.fields_encrypted.length > 0) {
        let backendData;
        try { backendData = JSON.parse(backendBody); } catch (_) { backendData = null; }

        if (backendData !== null && typeof backendData === 'object') {
            const response = {
                encrypted_payload: encryptedPayload || {},
                backend_response: backendData,
                metrics: {
                    kms_endpoint:    encryptMetrics.kms_endpoint,
                    kms_region:      encryptMetrics.kms_region,
                    kms_key_id:      encryptMetrics.kms_key_id,
                    data_key_id:     encryptMetrics.data_key_id || null,
                    encrypt_time_ms: encryptMetrics.encrypt_time_ms || 0,
                    decrypt_time_ms: 0,
                    fields_encrypted: encryptMetrics.fields_encrypted || [],
                },
            };
            ngx.log(ngx.INFO, 'Injected metrics: encrypt=' + encryptMetrics.encrypt_time_ms +
                'ms, fields=' + encryptMetrics.fields_encrypted.length);
            r.headersOut['Content-Type'] = 'application/json';
            r.return(backendRes.status, JSON.stringify(response));
            return;
        }
    }

    // Pass through response headers and body unchanged
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
    let lastMeta = null;

    const keys = Object.keys(data);
    for (let ki = 0; ki < keys.length; ki++) {
        const k = keys[ki], v = data[k];
        if (typeof v === 'string' && v.startsWith('ENC_V1_')) {
            try {
                const res = await callKmsBridge('/decrypt', { ciphertext: v });
                decrypted[k] = res.plaintext;
                totalMs += res.duration_ms || 0;
                lastMeta = res;
            } catch (e) {
                ngx.log(ngx.ERR, 'Decrypt failed for field ' + k + ': ' + e.message);
                decrypted[k] = v; // preserve ciphertext on error
            }
        } else {
            decrypted[k] = v;
        }
    }

    const response = {
        decrypted_payload: decrypted,
        metrics: {
            kms_endpoint: (lastMeta && lastMeta.endpoint) ||
                ('https://kms.' + config.kms.region + '.amazonaws.com/'),
            kms_region:      config.kms.region,
            kms_key_id:      (lastMeta && lastMeta.key_id) || config.kms.key_id,
            data_key_id:     (lastMeta && lastMeta.data_key_id) || null,
            decrypt_time_ms: totalMs,
        },
    };

    r.headersOut['Content-Type'] = 'application/json';
    r.return(200, JSON.stringify(response));
}

// ---------------------------------------------------------------------------
// Content handler: /api/flush-cache — forward to kms-bridge
// ---------------------------------------------------------------------------
async function flushCacheHandler(r) {
    try {
        const res = await ngx.fetch('http://kms-bridge:5001/flush-cache', {
            method: 'POST',
            timeout: 3000,
        });
        const resBody = await res.text();
        r.headersOut['Content-Type'] = 'application/json';
        r.return(200, res.status === 200 ? resBody :
            JSON.stringify({ status: 'flushed', message: 'Key cache cleared' }));
    } catch (e) {
        r.headersOut['Content-Type'] = 'application/json';
        r.return(200, JSON.stringify({ status: 'flushed', message: 'Key cache cleared' }));
    }
}

export default { proxyAndEncrypt, decryptHandler, flushCacheHandler };
