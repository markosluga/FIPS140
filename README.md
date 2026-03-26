# FIPS-140 Field Encryption Demo

> **Local development**
> This repo is for running the demo locally with Docker Compose. To deploy on EC2 instead, see [markosluga/FIPS140-ec2](https://github.com/markosluga/FIPS140-ec2).

## TL:DR

This is a 2 step process:
1. Phase 1: Demonstrates field-level encryption via AWS KMS, transparent to the app. NGINX intercepts requests, encrypts sensitive fields before they are sent to the backend.
2. Phase 2: Back-end retrieves the key from KMS and decrypts.

We're demonstrating a way to implement end-to-end encryption with practically any back-end service, KMS is just used as an example.

**And it's as easy as 1-2!**

## A word of caution

While we follow best practices all the way, the logger is used to demo what is happening and **logs in plain-text** - because it's a demo and we want to show what's happening in the background - if you EVER want to reuse any of this code know that this code as-is, is NOT in any sense meant for actual use or even production.

## Prerequisites

- Docker + Docker Compose
- AWS credentials with KMS access

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
docker-compose up
```

Open [http://localhost](http://localhost).

## Usage

1. **Phase 1** — enter a credit card number and click Encrypt. Use any [Stripe test card](https://docs.stripe.com/testing) e.g. `4242 4242 4242 4242`.
2. **Phase 2** — click Decrypt to retrieve the plaintext via KMS.

## Architecture

```
Browser → NGINX (encrypt) → Backend → NGINX (decrypt) → Browser
                ↕                           ↕
           KMS Bridge                  KMS Bridge
                ↕                           ↕
            AWS KMS                     AWS KMS
```

| Service     | Port | Role                                        |
|-------------|------|---------------------------------------------|
| nginx       | 80   | Encryption proxy + Web UI                   |
| backend     | 5000 | Echo API                                    |
| kms-bridge  | 5001 | AWS KMS HTTP bridge with encryption support |

## NGINX implementation

Uses **njs (NGINX JavaScript)** — the `ngx_http_js_module` module bundled with standard `nginx:alpine`. The encryption logic lives in `nginx/js/encryption_module.js` and is loaded via `nginx/Dockerfile.njs`.
