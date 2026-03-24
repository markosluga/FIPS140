"""AWS KMS Client with Signature V4 signing. Requirements: 2.1-2.5, 7.1, 7.4-7.5, 8.2-8.3"""
import os, time, json, base64, hashlib, hmac, requests
from datetime import datetime

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
    
    def encrypt(self, plaintext, key_id=None):
        """Encrypt plaintext, return {ciphertext, duration_ms, endpoint, region, key_id}"""
        start = time.time()
        key = key_id or self.key_id
        if not key:
            raise KMSClientError("key_id required")
        body = json.dumps({'KeyId': key, 'Plaintext': base64.b64encode(plaintext.encode()).decode()})
        try:
            resp = self._request('TrentService.Encrypt', body)
            return {
                'ciphertext': resp['CiphertextBlob'],
                'duration_ms': round((time.time() - start) * 1000, 2),
                'endpoint': self.endpoint,
                'region': self.region,
                'key_id': resp.get('KeyId', key)
            }
        except requests.exceptions.Timeout:
            raise KMSClientError("KMS timeout - service unavailable")
        except requests.exceptions.ConnectionError:
            raise KMSClientError("Cannot reach KMS - network error")
        except Exception as e:
            raise KMSClientError(f"Encryption failed: {e}")
    
    def decrypt(self, ciphertext):
        """Decrypt ciphertext, return {plaintext, duration_ms, endpoint, region, key_id}"""
        start = time.time()
        body = json.dumps({'CiphertextBlob': ciphertext})
        try:
            resp = self._request('TrentService.Decrypt', body)
            plaintext = base64.b64decode(resp['Plaintext']).decode()
            return {
                'plaintext': plaintext,
                'duration_ms': round((time.time() - start) * 1000, 2),
                'endpoint': self.endpoint,
                'region': self.region,
                'key_id': resp.get('KeyId', 'unknown')
            }
        except requests.exceptions.Timeout:
            raise KMSClientError("KMS timeout - service unavailable")
        except requests.exceptions.ConnectionError:
            raise KMSClientError("Cannot reach KMS - network error")
        except Exception as e:
            raise KMSClientError(f"Decryption failed: {e}")
    
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
        # Canonical request
        canonical_headers = '\n'.join(f"{k.lower()}:{v}" for k, v in sorted(headers.items())) + '\n'
        signed_headers = ';'.join(sorted(k.lower() for k in headers.keys()))
        payload_hash = hashlib.sha256(body.encode()).hexdigest()
        canonical = f"POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        # String to sign
        algorithm = 'AWS4-HMAC-SHA256'
        scope = f"{date_stamp}/{self.region}/kms/aws4_request"
        canonical_hash = hashlib.sha256(canonical.encode()).hexdigest()
        string_to_sign = f"{algorithm}\n{amz_date}\n{scope}\n{canonical_hash}"
        # Signature
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
