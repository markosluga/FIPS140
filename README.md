# FIPS-140 Field Encryption Demo

> **Local development**
> This repo is for running the demo locally with Docker Compose. To deploy on EC2 instead, see [markosluga/FIPS140-ec2](https://github.com/markosluga/FIPS140-ec2).

## TL;DR

This is a 2-step process:

1. **Phase 1:** NGINX intercepts the request, signs and calls AWS KMS directly to generate an ephemeral data key (DEK), encrypts the sensitive field with AES-256-GCM using the WebCrypto API, and forwards only the ciphertext envelope to the backend. The DEK never leaves NGINX memory.
2. **Phase 2:** The backend receives the encrypted payload, calls KMS directly to decrypt the envelope, and logs the recovered plaintext — demonstrating the full round-trip.

This demonstrates a way to implement transparent field-level encryption in front of practically any backend service, with NGINX doing all the crypto work inline — no sidecar, no proxy, no extra hop.

**And it's as easy as 1-2!**

## A word of caution

While we follow best practices all the way, the logger is used to demo what is happening and **logs in plain-text** — because it's a demo and we want to show what's happening in the background. If you ever want to reuse any of this code, know that this code as-is is NOT meant for actual production use.

## Prerequisites

- Docker + Docker Compose
- AWS credentials with KMS access (`kms:GenerateDataKey`, `kms:Decrypt`, `kms:DescribeKey`)

## Setup

```bash
export AWS_ACCESS_KEY_ID=your-key
export AWS_SECRET_ACCESS_KEY=your-secret
export AWS_SESSION_TOKEN=your-token  # if using temporary credentials
```

Create a KMS key and alias:

```bash
KEY_ID=$(aws kms create-key --description "demo-field-encryption" --query 'KeyMetadata.KeyId' --output text)
aws kms create-alias --alias-name alias/demo-field-encryption --target-key-id $KEY_ID
```

## Run

```bash
docker-compose up -d
```

Open [http://localhost](http://localhost).

## Usage

1. **Phase 1** — enter a credit card number and click Encrypt. Use any [Stripe test card](https://docs.stripe.com/testing) e.g. `4242 4242 4242 4242`.
2. **Phase 2** — click Decrypt to retrieve the plaintext via KMS.

---

## Architecture

```
Browser → NGINX (SigV4 + WebCrypto) → Backend (KMS direct) → Browser
                    ↕                          ↕
               AWS KMS                     AWS KMS
```

| Service  | Port | Role                                                    |
|----------|------|---------------------------------------------------------|
| nginx    | 80   | Encryption proxy + Web UI — calls KMS directly via njs  |
| backend  | 5000 | Receives encrypted payload, decrypts via KMS, echoes back |

## How encryption works

NGINX handles the full encrypt/decrypt path inline using two standard APIs — no sidecar process required:

**Encrypt (Phase 1):**
1. NGINX intercepts the POST request
2. njs calls `KMS.GenerateDataKey` directly, signed with **AWS SigV4** (implemented in `crypto.subtle` HMAC-SHA256)
3. njs encrypts the field locally with **AES-256-GCM** via the WebCrypto API (`crypto.subtle.encrypt`)
4. The plaintext DEK is zeroed immediately after use
5. The ciphertext envelope (`ENC_V1_...`) — containing the encrypted DEK, IV, and ciphertext — is forwarded to the backend in place of the plaintext value

**Decrypt (Phase 2):**
1. The frontend sends the stored ciphertext back to NGINX `/api/decrypt`
2. njs unpacks the envelope, sends the encrypted DEK to `KMS.Decrypt`
3. njs decrypts locally with AES-256-GCM and returns the plaintext

**Backend:**
The Flask backend receives the encrypted payload, calls `KMS.Decrypt` directly using `kms_client.py`, logs the recovered plaintext, and echoes the decrypted data back — demonstrating the full server-side flow independently of NGINX.

## Envelope format

Each encrypted field is a self-contained envelope:

```
ENC_V1_<base64(JSON)>
```

Where the JSON contains:
```json
{
  "v": 1,
  "edk": "<base64 — encrypted DEK, unwrapped by KMS on decrypt>",
  "iv":  "<base64 — 12-byte random nonce>",
  "ct":  "<base64 — AES-256-GCM ciphertext + auth tag>"
}
```

The envelope is portable — decryption only needs the envelope itself and KMS access. No separate key lookup required.

## IAM permissions required

```json
{
  "Effect": "Allow",
  "Action": [
    "kms:GenerateDataKey",
    "kms:Decrypt",
    "kms:DescribeKey"
  ],
  "Resource": "*"
}
```
