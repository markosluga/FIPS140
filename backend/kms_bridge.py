"""HTTP bridge for KMS operations. Provides REST API for Lua module."""
from flask import Flask, request, jsonify
import logging
import re
import sys
from kms_client import KMSClient, KMSClientError
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)

app = Flask(__name__)
logger = logging.getLogger(__name__)

# Initialize KMS client
kms_client = None
config = None

# Valid JSONPath: starts with $. followed by dot-separated identifiers
# Supports: $.field  $.parent.child  $.a.b.c
# Rejects: $..field (double dots), $.* (wildcards), $.field[0] (arrays)
_VALID_PATH_RE = re.compile(r'^\$(\.[a-zA-Z_][a-zA-Z0-9_]*)+$')


def load_config(config_path='/etc/nginx/config.yaml'):
    """Load configuration from config.yaml"""
    global config
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        logger.info(
            f"Loaded config: region={config['kms']['region']}, "
            f"key_id={config['kms']['key_id']}"
        )
        return config
    except yaml.YAMLError as e:
        logger.error(f"ERROR: Invalid YAML syntax in config.yaml: {e}")
        raise
    except FileNotFoundError:
        logger.error(f"ERROR: Configuration file not found: {config_path}")
        raise
    except Exception as e:
        logger.error(f"Failed to load config: {e}")
        raise


def validate_config(cfg):
    """Validate config.yaml schema - required fields and field selector syntax.

    Raises ValueError with a clear message if validation fails.
    Requirements: 4.5
    """
    if not isinstance(cfg, dict):
        raise ValueError(
            "ERROR: Invalid configuration in config.yaml\n"
            "Configuration must be a YAML mapping"
        )

    if 'kms' not in cfg:
        raise ValueError(
            "ERROR: Invalid configuration in config.yaml\n"
            "Missing required section: 'kms'"
        )

    kms = cfg['kms']
    if not isinstance(kms, dict):
        raise ValueError(
            "ERROR: Invalid configuration in config.yaml\n"
            "'kms' must be a mapping"
        )

    if not kms.get('region'):
        raise ValueError(
            "ERROR: Invalid configuration in config.yaml\n"
            "Missing required field: 'kms.region'"
        )

    if not kms.get('key_id'):
        raise ValueError(
            "ERROR: Invalid configuration in config.yaml\n"
            "Missing required field: 'kms.key_id'"
        )

    if 'encryption' not in cfg:
        raise ValueError(
            "ERROR: Invalid configuration in config.yaml\n"
            "Missing required section: 'encryption'"
        )

    enc = cfg['encryption']
    if not isinstance(enc, dict) or 'fields' not in enc:
        raise ValueError(
            "ERROR: Invalid configuration in config.yaml\n"
            "Missing required field: 'encryption.fields'"
        )

    fields = enc['fields']
    if not isinstance(fields, list) or len(fields) == 0:
        raise ValueError(
            "ERROR: Invalid configuration in config.yaml\n"
            "'encryption.fields' must be a non-empty list"
        )

    for i, field in enumerate(fields):
        if not isinstance(field, dict):
            raise ValueError(
                f"ERROR: Invalid configuration in config.yaml\n"
                f"Field entry {i + 1} must be a mapping with a 'path' key"
            )
        path = field.get('path')
        if not path:
            raise ValueError(
                f"ERROR: Invalid configuration in config.yaml\n"
                f"Field entry {i + 1} is missing required 'path' key"
            )
        if not _VALID_PATH_RE.match(path):
            raise ValueError(
                f"ERROR: Invalid configuration in config.yaml\n"
                f"Field selector '{path}' has invalid syntax "
                f"(use dot notation like $.field or $.parent.child; "
                f"double dots, wildcards, and array notation are not supported)"
            )

    logger.info(
        f"Configuration validated: region={kms['region']}, "
        f"key_id={kms['key_id']}, fields={len(fields)}"
    )
    return True


def validate_kms_key(client, key_id):
    """Call DescribeKey to verify the KMS key exists and is accessible.

    Fails with a clear error message if not.
    Requirements: 7.3, 7.5
    """
    try:
        metadata = client.describe_key(key_id)
        key_state = metadata.get('KeyState', 'Unknown')
        if key_state not in ('Enabled', 'PendingImport'):
            raise ValueError(
                f"ERROR: KMS key '{key_id}' exists but is not enabled "
                f"(state: {key_state})\n"
                f"Enable the key in the AWS KMS console before starting the demo"
            )
        logger.info(f"KMS key verified: {key_id} (state={key_state})")
        return True
    except KMSClientError as e:
        err_str = str(e)
        if 'NotFoundException' in err_str or 'not found' in err_str.lower():
            raise ValueError(
                f"ERROR: KMS key '{key_id}' not found or not accessible\n"
                f"Check: 1) Key exists in region {client.region}, "
                f"2) AWS credentials are valid, "
                f"3) IAM permissions include kms:DescribeKey"
            )
        if 'Access denied' in err_str or 'AccessDenied' in err_str:
            raise ValueError(
                f"ERROR: KMS key '{key_id}' not found or not accessible\n"
                f"Check: 1) Key exists in region {client.region}, "
                f"2) AWS credentials are valid, "
                f"3) IAM permissions include kms:DescribeKey"
            )
        raise ValueError(
            f"ERROR: KMS key '{key_id}' not found or not accessible\n"
            f"Detail: {err_str}"
        )


@app.route('/flush-cache', methods=['POST'])
def flush_cache():
    """Flush the KMS data key cache (simulated for demo)."""
    logger.info("[FLUSH] Key cache flushed")
    return jsonify({"status": "flushed", "message": "Key cache cleared — next operation will re-request keys from AWS KMS"}), 200


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({"status": "healthy"}), 200


@app.route('/encrypt', methods=['POST'])
def encrypt():
    """
    Encrypt plaintext using KMS.
    Request: {"plaintext": "value", "key_id": "optional"}
    Response: {"ciphertext": "base64", "duration_ms": 123, "endpoint": "...", "key_id": "..."}
    """
    try:
        data = request.get_json()
        if not data or 'plaintext' not in data:
            return jsonify({"error": "Missing 'plaintext' field"}), 400

        plaintext = data['plaintext']
        key_id = data.get('key_id', config['kms']['key_id'])

        logger.info(f"[ENCRYPT] Encrypting field (length={len(plaintext)})")
        result = kms_client.encrypt(plaintext, key_id)
        logger.info(f"[ENCRYPTED] Duration: {result['duration_ms']}ms, Key: {result['key_id']}")

        return jsonify(result), 200

    except KMSClientError as e:
        logger.error(f"KMS encryption error: {e}")
        return jsonify({"error": str(e)}), 503
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        return jsonify({"error": f"Encryption failed: {e}"}), 500


@app.route('/decrypt', methods=['POST'])
def decrypt():
    """
    Decrypt ciphertext using KMS.
    Request: {"ciphertext": "base64"}
    Response: {"plaintext": "value", "duration_ms": 123, "endpoint": "...", "key_id": "..."}
    """
    try:
        data = request.get_json()
        if not data or 'ciphertext' not in data:
            return jsonify({"error": "Missing 'ciphertext' field"}), 400

        ciphertext = data['ciphertext']

        logger.info(f"[DECRYPT] Decrypting field (length={len(ciphertext)})")
        result = kms_client.decrypt(ciphertext)
        logger.info(f"[DECRYPTED] Duration: {result['duration_ms']}ms, Value: {result['plaintext'][:20]}...")

        return jsonify(result), 200

    except KMSClientError as e:
        logger.error(f"KMS decryption error: {e}")
        return jsonify({"error": str(e)}), 503
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        return jsonify({"error": f"Decryption failed: {e}"}), 500


if __name__ == '__main__':
    logger.info("Starting KMS HTTP Bridge on port 5001")

    # Load configuration
    try:
        load_config()
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        sys.exit(1)

    # Validate configuration schema and field selectors (Requirement 4.5)
    try:
        validate_config(config)
    except ValueError as e:
        logger.error(str(e))
        sys.exit(1)

    # Validate AWS credentials are present (Requirement 7.5)
    try:
        kms_client = KMSClient(
            region=config['kms']['region'],
            key_id=config['kms']['key_id']
        )
        logger.info("AWS credentials found and KMS client initialized")
    except KMSClientError as e:
        logger.error(
            "ERROR: AWS credentials not found or invalid\n"
            "Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables\n"
            f"Detail: {e}"
        )
        sys.exit(1)

    # Validate KMS key exists and is accessible (Requirement 7.3)
    try:
        validate_kms_key(kms_client, config['kms']['key_id'])
    except ValueError as e:
        logger.error(str(e))
        sys.exit(1)

    logger.info("Startup validation complete")
    logger.info("Endpoints:")
    logger.info("  POST /encrypt - Encrypt plaintext")
    logger.info("  POST /decrypt - Decrypt ciphertext")
    logger.info("  GET  /health  - Health check")

    app.run(host='0.0.0.0', port=5001, debug=False)
