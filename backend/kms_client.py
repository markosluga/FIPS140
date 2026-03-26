"""AWS KMS Client with Signature V4 signing. Requirements: 2.1-2.5, 7.1, 7.4-7.5, 8.2-8.3"""
import os, time, json, base64, hashlib, hmac, requests
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class KMSClientError(Exception):
    pass

class KMSClient:
    def __init__(self, region=None, key_id=None):
        self.region = region or os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')
        self.key_id = key_id
        self.endpoint = f"https://kms.{self.region}.amazonaws.com/"
        self.access_key = os.environ.get('AWS_ACCESS_KEY_ID')
        self.secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
        self.session_token = os.environ.get('AWS_SESSION_TOKEN')
        if not self.access_key or not self.secret_key:
            raise KMSClientError("AWS credentials not found. Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")

    def _generate_data_key(self, key_id):
        """Call KMS GenerateDataKey to get a one-time AES-256 DEK."""
        body = json.dumps({'KeyId': key_id, 'KeySpec': 'AES_256'})
        try:
            resp = self._request('TrentService.GenerateDataKey', body)
            return {
                'plaintext_key': base64.b64decode(resp['Plaintext']),  # raw bytes — discard after use
                'encrypted_key': resp['CiphertextBlob'],               # EDK — safe to store
                'cmk_id': resp.get('KeyId', key_id),
            }
        except requests.exceptions.Timeout:
            raise KMSClientError("KMS timeout generating data key")
        except requests.exceptions.ConnectionError:
            raise KMSClientError("Cannot reach KMS - network error")
        except KMSClientError:
            raise
        except Exception as e:
            raise KMSClientError(f"GenerateDataKey failed: {e}")

    def encrypt(self, plaintext, key_id=None):
        """Envelope-encrypt plaintext: GenerateDataKey → AES-256-GCM → discard DEK.
        Returns {ciphertext, data_key_id, duration_ms, endpoint, region, key_id}
        """
        start = time.time()
        key = key_id or self.key_id
        if not key:
            raise KMSClientError("key_id required")

        # 1. Get ephemeral DEK from KMS
        dek = self._generate_data_key(key)
        dek_bytes = dek['plaintext_key']
        edk = dek['encrypted_key']  # base64-encoded, safe to store

        try:
            # 2. Encrypt data locally with AES-256-GCM
            nonce = os.urandom(12)
            aesgcm = AESGCM(dek_bytes)
            ct_bytes = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        finally:
            # 3. Discard plaintext DEK immediately
            dek_bytes = bytes(len(dek_bytes))

        # 4. Pack envelope: version + EDK + nonce + ciphertext, prefixed for detection
        envelope = json.dumps({
            'v': 1,
            'edk': edk,
            'iv':  base64.b64encode(nonce).decode(),
            'ct':  base64.b64encode(ct_bytes).decode(),
        })
        ciphertext = 'ENC_V1_' + base64.b64encode(envelope.encode()).decode()

        return {
            'ciphertext':   ciphertext,
            'data_key_id':  edk[:32] + '…',   # truncated EDK as display handle
            'duration_ms':  round((time.time() - start) * 1000, 2),
            'endpoint':     self.endpoint,
            'region':       self.region,
            'key_id':       dek['cmk_id'],
        }

    def decrypt(self, ciphertext):
        """Envelope-decrypt: unpack envelope → KMS.Decrypt(EDK) → AES-256-GCM decrypt → discard DEK.
        Returns {plaintext, data_key_id, duration_ms, endpoint, region, key_id}
        """
        start = time.time()

        if not ciphertext.startswith('ENC_V1_'):
            raise KMSClientError("Unknown ciphertext format — expected ENC_V1_ prefix")

        try:
            envelope = json.loads(base64.b64decode(ciphertext[7:]).decode())
            edk      = envelope['edk']
            nonce    = base64.b64decode(envelope['iv'])
            ct_bytes = base64.b64decode(envelope['ct'])
        except Exception as e:
            raise KMSClientError(f"Malformed envelope ciphertext: {e}")

        # 1. Recover DEK via KMS
        body = json.dumps({'CiphertextBlob': edk})
        try:
            resp = self._request('TrentService.Decrypt', body)
            dek_bytes = base64.b64decode(resp['Plaintext'])
            cmk_id = resp.get('KeyId', 'unknown')
        except requests.exceptions.Timeout:
            raise KMSClientError("KMS timeout - service unavailable")
        except requests.exceptions.ConnectionError:
            raise KMSClientError("Cannot reach KMS - network error")
        except KMSClientError:
            raise
        except Exception as e:
            raise KMSClientError(f"Decryption failed: {e}")

        try:
            # 2. Decrypt data locally
            aesgcm = AESGCM(dek_bytes)
            plaintext = aesgcm.decrypt(nonce, ct_bytes, None).decode('utf-8')
        except Exception as e:
            raise KMSClientError(f"AES-GCM decryption failed: {e}")
        finally:
            # 3. Discard plaintext DEK immediately
            dek_bytes = bytes(len(dek_bytes))

        return {
            'plaintext':   plaintext,
            'data_key_id': edk[:32] + '…',
            'duration_ms': round((time.time() - start) * 1000, 2),
            'endpoint':    self.endpoint,
            'region':      self.region,
            'key_id':      cmk_id,
        }

    def _request(self, target, body, timeout=5):
        """Make signed KMS API request"""
        headers = {'Content-Type': 'application/x-amz-json-1.1', 'X-Amz-Target': target}
        signed = self._sign(headers, body)
        resp = requests.post(self.endpoint, headers=signed, data=body, timeout=timeout)
        if resp.status_code != 200:
            err = resp.json() if resp.text else {}
            err_type = err.get('__type', 'Unknown')
            err_msg = err.get('message', resp.text)
            if 'ThrottlingException' in err_type:
                raise KMSClientError(f"KMS throttled: {err_msg}")
            elif 'InvalidCiphertextException' in err_type:
                raise KMSClientError(f"Invalid ciphertext: {err_msg}")
            elif 'AccessDeniedException' in err_type:
                raise KMSClientError(f"Access denied: {err_msg}")
            else:
                raise KMSClientError(f"KMS error ({err_type}): {err_msg}")
        return resp.json()

    def _sign(self, headers, body):
        """AWS Signature V4 signing"""
        t = datetime.utcnow()
        amz_date = t.strftime('%Y%m%dT%H%M%SZ')
        date_stamp = t.strftime('%Y%m%d')
        headers = headers.copy()
        headers['X-Amz-Date'] = amz_date
        headers['Host'] = f"kms.{self.region}.amazonaws.com"
        if self.session_token:
            headers['X-Amz-Security-Token'] = self.session_token
        canonical_headers = '\n'.join(f"{k.lower()}:{v}" for k, v in sorted(headers.items())) + '\n'
        signed_headers = ';'.join(sorted(k.lower() for k in headers.keys()))
        payload_hash = hashlib.sha256(body.encode()).hexdigest()
        canonical = f"POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        algorithm = 'AWS4-HMAC-SHA256'
        scope = f"{date_stamp}/{self.region}/kms/aws4_request"
        canonical_hash = hashlib.sha256(canonical.encode()).hexdigest()
        string_to_sign = f"{algorithm}\n{amz_date}\n{scope}\n{canonical_hash}"
        k_date = hmac.new(f"AWS4{self.secret_key}".encode(), date_stamp.encode(), hashlib.sha256).digest()
        k_region = hmac.new(k_date, self.region.encode(), hashlib.sha256).digest()
        k_service = hmac.new(k_region, b'kms', hashlib.sha256).digest()
        k_signing = hmac.new(k_service, b'aws4_request', hashlib.sha256).digest()
        signature = hmac.new(k_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()
        headers['Authorization'] = f"{algorithm} Credential={self.access_key}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
        return headers

    def describe_key(self, key_id=None):
        """Call DescribeKey to verify key exists and is accessible"""
        key = key_id or self.key_id
        if not key:
            raise KMSClientError("key_id required for DescribeKey")
        body = json.dumps({'KeyId': key})
        try:
            resp = self._request('TrentService.DescribeKey', body)
            return resp.get('KeyMetadata', {})
        except requests.exceptions.Timeout:
            raise KMSClientError(f"KMS timeout verifying key '{key}'")
        except requests.exceptions.ConnectionError:
            raise KMSClientError(f"Cannot reach KMS to verify key '{key}'")
        except KMSClientError:
            raise
        except Exception as e:
            raise KMSClientError(f"DescribeKey failed for '{key}': {e}")


def validate_credentials():
    """Validate AWS credentials at startup"""
    try:
        KMSClient()
        return True
    except KMSClientError as e:
        raise KMSClientError(f"Credential validation failed: {e}")
