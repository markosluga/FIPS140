# NGINX + AWS KMS Field-Level Encryption Demo

A minimal demonstration system showcasing field-level encryption using NGINX integrated with AWS KMS (FIPS 140-3 Level 3 HSM-backed encryption).

## Overview

This demo intercepts HTTP traffic through NGINX, encrypts sensitive JSON fields using AWS KMS, and demonstrates the complete encryption flow through an interactive web interface with real-time metrics.

## Architecture

Three services work together:

- **nginx** (port 80): Intercepts requests/responses, applies field-level encryption via Lua module, serves the Web UI
- **backend** (port 5000, internal): Simple Python app that receives encrypted data and returns responses
- **kms-bridge** (port 5001, internal): Python service that handles all AWS KMS API calls

```
Client → nginx:80 → backend:5000
              ↕
         kms-bridge:5001 → AWS KMS
```

## Prerequisites

### 1. AWS Account Setup

- Active AWS account with access to KMS service
- AWS credentials with KMS permissions:
  - `kms:Encrypt`
  - `kms:Decrypt`
  - `kms:DescribeKey`

### 2. KMS Key Creation

Create a KMS key backed by FIPS 140-3 Level 3 HSM:

```bash
# Create KMS key
aws kms create-key \
  --description "Demo field encryption key" \
  --key-spec SYMMETRIC_DEFAULT \
  --origin AWS_KMS

# Create alias (use the KeyId from previous command)
aws kms create-alias \
  --alias-name alias/demo-field-encryption \
  --target-key-id <KEY_ID>

# Verify key exists
aws kms describe-key --key-id alias/demo-field-encryption
```

### 3. AWS Credentials

Set environment variables before starting the demo:

```bash
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_REGION="us-east-1"
```

Or use `AWS_SESSION_TOKEN` if using temporary credentials (e.g., assumed role).

### 4. Docker and Docker Compose

- Docker Engine 20.10+
- Docker Compose 2.0+

## Setup Instructions

### Step 1: Clone and Configure

```bash
# Clone repository (or extract demo files)
cd nginx-kms-field-encryption-demo

# Edit config.yaml if needed (default uses us-east-1 and alias/demo-field-encryption)
nano config.yaml
```

### Step 2: Set AWS Credentials

```bash
# Option 1: Environment variables (recommended)
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_REGION="us-east-1"

# Option 2: Create .env file (not committed to git)
cat > .env << EOF
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
AWS_REGION=us-east-1
EOF
```

### Step 3: Start the Demo

```bash
# Start all services
docker-compose up

# Or run in background
docker-compose up -d

# View logs
docker-compose logs -f
```

All three services start with this single command. The demo will be available at: **http://localhost:80**

### Step 4: Stop the Demo

```bash
docker-compose down
```

## Using the Demo

### Web UI

Open your browser to **http://localhost** (port 80).

1. Enter sensitive data in the form:
   - Social Security Number: `123-45-6789`
   - Credit Card: `4532-1234-5678-9010`
   - Name: `John Doe` (non-sensitive, will not be encrypted)
2. Click "Encrypt & Process"
3. Observe:
   - Encryption flow visualization
   - KMS endpoint and timing metrics
   - Original vs encrypted vs decrypted data

### curl Commands

```bash
# Test encryption flow
curl -X POST http://localhost/api/encrypt \
  -H "Content-Type: application/json" \
  -d '{
    "ssn": "123-45-6789",
    "credit_card": "4532-1234-5678-9010",
    "name": "John Doe"
  }'

# Test decryption (pass an encrypted payload back)
curl -X POST http://localhost/api/decrypt \
  -H "Content-Type: application/json" \
  -d '{
    "ssn": "AQICAHh...<base64-ciphertext>",
    "credit_card": "AQICAHh...<base64-ciphertext>",
    "name": "John Doe"
  }'

# Health check
curl http://localhost/health
```

### Before/After Examples

**Request sent by client (plaintext):**
```json
{
  "ssn": "123-45-6789",
  "credit_card": "4532-1234-5678-9010",
  "name": "John Doe"
}
```

**What the backend receives (encrypted fields):**
```json
{
  "ssn": "AQICAHh5k2XvZ9...truncated...==",
  "credit_card": "AQICAHh7mNpQr3...truncated...==",
  "name": "John Doe"
}
```

**Response returned to client (decrypted by NGINX):**
```json
{
  "ssn": "123-45-6789",
  "credit_card": "4532-1234-5678-9010",
  "name": "John Doe",
  "status": "processed"
}
```

The `name` field is never encrypted — only fields listed in `config.yaml` are touched. The backend never sees plaintext SSN or credit card numbers.

### Viewing Logs

```bash
# NGINX logs (shows encryption/decryption operations)
docker-compose logs nginx

# Backend logs (shows encrypted data received)
docker-compose logs backend

# KMS bridge logs (shows KMS API calls and timing)
docker-compose logs kms-bridge

# Follow all logs
docker-compose logs -f
```

## Configuration

### Field Selectors

Edit `config.yaml` to define which fields to encrypt:

```yaml
kms:
  region: us-east-1
  key_id: alias/demo-field-encryption

encryption:
  fields:
    - path: $.ssn
      description: Social Security Number
    - path: $.credit_card
      description: Credit Card Number
    - path: $.patient.medical_record_number
      description: Nested medical record
```

Supported syntax:
- `$.field_name` — top-level field
- `$.parent.child` — nested field (dot notation, up to 3 levels)

## Demo Script for Presentations

### Introduction (1 minute)

"Today I'll demonstrate field-level encryption using NGINX and AWS KMS with FIPS 140-3 Level 3 HSM backing."

### Live Demo (3 minutes)

1. **Show the web interface** at http://localhost
2. **Enter sensitive data** — SSN, credit card, name
3. **Submit and explain the flow**
   - "Watch the encryption flow — data goes through 5 steps"
   - Point out KMS endpoint: `https://kms.us-east-1.amazonaws.com/`
   - Show timing metrics: "Encryption took ~140ms, decryption ~138ms"
4. **Show encrypted data**
   - "The SSN and credit card are now KMS ciphertext"
   - "The name field stays plaintext — only configured fields are encrypted"
5. **Show backend logs**
   ```bash
   docker-compose logs backend | tail -5
   ```
   - "The backend receives encrypted data — it never sees plaintext SSN"
6. **Show decrypted response**
   - "NGINX decrypts the response before returning to the client"

### Technical Details (2 minutes)

1. **Show configuration**
   ```bash
   cat config.yaml
   ```
   - "12 lines of config — defines which fields to encrypt using JSONPath"

2. **Explain KMS integration**
   - "Every encryption call goes to AWS KMS HSM"
   - "FIPS 140-3 Level 3 validated hardware security module"
   - "Keys never leave the HSM"

3. **Show NGINX module** (optional)
   - "The Lua module is under 300 lines"
   - "Intercepts requests/responses transparently — no app changes needed"

### Q&A Points

**Q: What's the performance impact?**
A: "~140ms per KMS call. For production, use caching and async operations."

**Q: Can it handle nested fields?**
A: "Yes — `$.patient.medical_record_number` works out of the box."

**Q: What happens if KMS is unavailable?**
A: "The system fails secure — returns 503 rather than sending plaintext."

**Q: Does this work with existing applications?**
A: "Yes — transparent to the backend. No application changes needed."

## Project Structure

```
.
├── config.yaml              # Field encryption configuration
├── docker-compose.yml       # Service orchestration (nginx, backend, kms-bridge)
├── nginx/
│   ├── Dockerfile           # OpenResty (NGINX + Lua) image
│   ├── nginx.conf           # NGINX configuration
│   ├── lua/
│   │   └── encryption_module.lua  # Field encryption/decryption logic
│   └── html/
│       ├── index.html       # Demo Web UI
│       ├── app.js           # UI logic
│       └── styles.css       # UI styling
├── backend/
│   ├── Dockerfile           # Backend service image
│   ├── Dockerfile.bridge    # KMS bridge service image
│   ├── app.py               # Sample Python backend (port 5000)
│   ├── kms_bridge.py        # KMS bridge service (port 5001)
│   ├── kms_client.py        # AWS KMS client library
│   └── requirements.txt     # Python dependencies
└── README.md                # This file
```

## Troubleshooting

### Error: "KMS key not found"

```bash
# Verify key exists
aws kms describe-key --key-id alias/demo-field-encryption

# Check region matches config.yaml
aws configure get region
```

### Error: "AWS credentials not found"

```bash
# Verify credentials are set
echo $AWS_ACCESS_KEY_ID
echo $AWS_SECRET_ACCESS_KEY

# Or check .env file exists
cat .env
```

### Error: "Access denied" from KMS

```bash
# Test KMS access directly
aws kms encrypt \
  --key-id alias/demo-field-encryption \
  --plaintext "test" \
  --query CiphertextBlob \
  --output text
```

Required IAM policy:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:DescribeKey"
      ],
      "Resource": "arn:aws:kms:us-east-1:*:key/*"
    }
  ]
}
```

### Services not starting

```bash
# Check all service logs
docker-compose logs

# Rebuild images if code changed
docker-compose up --build

# Check which containers are running
docker-compose ps
```

### Logs show "Connection timeout" to KMS

- Check internet connectivity from the container
- Verify `AWS_REGION` matches the region where your key was created
- Check if a firewall blocks outbound HTTPS to AWS endpoints

### Web UI not loading

- Confirm nginx container is running: `docker-compose ps`
- Check nginx logs: `docker-compose logs nginx`
- Ensure port 80 is not already in use on your machine

## Security Notes

- **Demo Only**: This is a demonstration system, not production-ready
- **Credentials**: Never commit AWS credentials to git — use environment variables or `.env` (gitignored)
- **KMS Costs**: Each encrypt/decrypt call costs ~$0.03 per 10,000 requests
- **FIPS 140-3**: Ensure your KMS key is created in a region with FIPS 140-3 Level 3 HSMs
- **Network**: All KMS calls use HTTPS (TLS 1.2+); backend and kms-bridge are not exposed externally

## License

This demo is provided as-is for educational and demonstration purposes.
