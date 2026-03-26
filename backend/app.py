"""Flask application with API endpoint. Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 8.4"""
from flask import Flask, request, jsonify
import logging
import sys
import json
import requests

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)

app = Flask(__name__)
logger = logging.getLogger(__name__)

KMS_BRIDGE_URL = 'http://kms-bridge:5001'


def decrypt_field(ciphertext):
    """Call kms-bridge to decrypt a single ENC_V1_ ciphertext value."""
    resp = requests.post(
        f'{KMS_BRIDGE_URL}/decrypt',
        json={'ciphertext': ciphertext},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


@app.route('/api/submit', methods=['POST'])
def submit():
    """
    Accept JSON payloads, decrypt any ENC_V1_ fields via kms-bridge, and echo back.

    Requirements:
    - 3.1: Expose HTTP endpoint that accepts JSON payloads
    - 3.2: Return JSON responses containing sensitive fields
    - 3.3: Log received requests to demonstrate encrypted data reaches backend
    """
    try:
        if not request.is_json:
            logger.warning(f"Received request with non-JSON content type: {request.content_type}")
            return jsonify({"error": "Content-Type must be application/json"}), 400

        data = request.get_json()
        if data is None:
            logger.warning("Received request with no JSON body")
            return jsonify({"error": "No JSON body provided"}), 400

        logger.info("=" * 60)
        logger.info("BACKEND RECEIVED REQUEST")
        logger.info("=" * 60)
        logger.info(f"Raw payload: {json.dumps(data, indent=2)}")

        decrypted = {}
        decrypt_metrics = {}

        for key, value in data.items():
            if isinstance(value, str) and value.startswith('ENC_V1_'):
                logger.info(f"[ENCRYPTED FIELD] {key}: {value[:60]}...")
                logger.info(f"[KMS] Calling kms-bridge to decrypt field '{key}'")
                try:
                    result = decrypt_field(value)
                    decrypted[key] = result['plaintext']
                    decrypt_metrics[key] = {
                        'duration_ms': result.get('duration_ms'),
                        'kms_key_id': result.get('key_id'),
                    }
                    logger.info(
                        f"[DECRYPTED] field='{key}' plaintext='{result['plaintext']}' "
                        f"kms_key={result.get('key_id')} duration={result.get('duration_ms')}ms"
                    )
                except Exception as e:
                    logger.error(f"[KMS ERROR] Failed to decrypt field '{key}': {e}")
                    decrypted[key] = value  # preserve ciphertext on error
            else:
                logger.info(f"[PLAINTEXT FIELD] {key}: {value}")
                decrypted[key] = value

        logger.info("=" * 60)

        response = {
            **decrypted,
            "processed": True,
            "backend_message": "Data received, decrypted, and processed successfully",
            "decrypt_metrics": decrypt_metrics,
        }

        logger.info(f"Sending response with {len(response)} fields")

        return jsonify(response), 200

    except Exception as e:
        logger.error(f"Error processing request: {str(e)}")
        return jsonify({
            "error": "Internal server error",
            "detail": str(e)
        }), 500


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({"status": "healthy"}), 200


if __name__ == '__main__':
    logger.info("Starting Flask application on port 5000")
    logger.info("Endpoints:")
    logger.info("  POST /api/submit - Accept, decrypt, and echo JSON payloads")
    logger.info("  GET  /health     - Health check")

    app.run(host='0.0.0.0', port=5000, debug=False)
