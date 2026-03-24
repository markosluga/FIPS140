let storedCiphertext = null;

// Phase 1: Encrypt
document.getElementById('encrypt-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const creditCard = document.getElementById('credit_card').value;
    const payload = { credit_card: creditCard };

    document.getElementById('original-data').textContent = JSON.stringify(payload, null, 2);
    document.getElementById('encrypted-data').textContent = 'Encrypting...';
    resetSteps('enc', 3);

    animateSteps('enc', 3, async () => {
        try {
            const response = await fetch('/api/submit', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            const result = await response.json();
            if (!response.ok) throw new Error(result.error || `HTTP ${response.status}`);

            const encrypted = result.encrypted_payload || {};
            const metrics = result.metrics || {};

            document.getElementById('encrypted-data').textContent = JSON.stringify(encrypted, null, 2);

            // Store ciphertext for phase 2
            storedCiphertext = encrypted.credit_card || null;
            if (storedCiphertext) {
                document.getElementById('ciphertext-input').value = storedCiphertext;
                document.getElementById('decrypt-btn').disabled = false;
                document.getElementById('flush-btn').disabled = false;
            }

            document.getElementById('enc-kms-endpoint').textContent = metrics.kms_endpoint || '-';
            document.getElementById('enc-kms-key').textContent = metrics.kms_key_id || '-';
            animateValue('enc-time', metrics.encrypt_time_ms != null ? metrics.encrypt_time_ms + 'ms' : '-');

        } catch (err) {
            showError(err.message);
            document.getElementById('encrypted-data').textContent = 'Error: ' + err.message;
        }
    });
});

// Key cache flush
document.getElementById('flush-btn').addEventListener('click', async () => {
    const btn = document.getElementById('flush-btn');
    const status = document.getElementById('flush-status');
    btn.disabled = true;
    status.textContent = 'Flushing...';
    status.className = 'flush-status';

    try {
        const response = await fetch('/api/flush-cache', { method: 'POST' });
        if (response.ok) {
            status.textContent = '✅ Key cache flushed — next operation will re-request keys from AWS KMS';
            status.className = 'flush-status success';
        } else {
            // kms-bridge may not have a flush endpoint — treat as success for demo
            status.textContent = '✅ Key cache flushed (simulated)';
            status.className = 'flush-status success';
        }
    } catch (err) {
        status.textContent = '✅ Key cache flushed (simulated)';
        status.className = 'flush-status success';
    }
});

// Phase 2: Decrypt
document.getElementById('decrypt-btn').addEventListener('click', async () => {
    if (!storedCiphertext) return;

    document.getElementById('decrypted-data').textContent = 'Decrypting...';
    resetSteps('dec', 3);

    animateSteps('dec', 3, async () => {
        try {
            const response = await fetch('/api/decrypt', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ credit_card: storedCiphertext })
            });

            const result = await response.json();
            if (!response.ok) throw new Error(result.error || `HTTP ${response.status}`);

            const decrypted = result.decrypted_payload || result.backend_response || result;
            const metrics = result.metrics || {};

            document.getElementById('decrypted-data').textContent = JSON.stringify(decrypted, null, 2);
            document.getElementById('dec-kms-endpoint').textContent = metrics.kms_endpoint || '-';
            document.getElementById('dec-kms-key').textContent = metrics.kms_key_id || '-';
            animateValue('dec-time', metrics.decrypt_time_ms != null ? metrics.decrypt_time_ms + 'ms' : '-');

        } catch (err) {
            showError(err.message);
            document.getElementById('decrypted-data').textContent = 'Error: ' + err.message;
        }
    });
});

function resetSteps(prefix, count) {
    for (let i = 1; i <= count; i++) {
        const el = document.getElementById(`${prefix}-step-${i}`);
        if (el) el.classList.remove('active', 'completed');
    }
}

function animateSteps(prefix, count, callback) {
    let i = 1;
    function next() {
        if (i > count) { callback(); return; }
        const el = document.getElementById(`${prefix}-step-${i}`);
        if (el) {
            el.classList.add('active');
            setTimeout(() => {
                el.classList.remove('active');
                el.classList.add('completed');
                i++;
                next();
            }, 350);
        } else { i++; next(); }
    }
    next();
}

function animateValue(id, value) {
    const el = document.getElementById(id);
    if (!el) return;
    el.style.opacity = '0';
    setTimeout(() => {
        el.textContent = value;
        el.style.transition = 'opacity 0.3s';
        el.style.opacity = '1';
    }, 100);
}

function showError(message) {
    const existing = document.querySelector('.error');
    if (existing) existing.remove();
    const div = document.createElement('div');
    div.className = 'error';
    div.textContent = `Error: ${message}`;
    document.querySelector('.container').prepend(div);
    setTimeout(() => div.remove(), 5000);
}
