"""Flask application with API endpoint. Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 8.4"""
from flask import Flask, request, jsonify
import logging
import sys
import json

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)

app = Flask(__name__)
logger = logging.getLogger(__name__)


@app.route('/api/submit', methods=['POST'])
def submit():
    """
    Accept JSON payloads and echo them back with additional fields.
    Logs received data to demonstrate encrypted fields reach backend.
    
    Requirements:
    - 3.1: Expose HTTP endpoint that accepts JSON payloads
    - 3.2: Return JSON responses containing sensitive fields
    - 3.3: Log received requests to demonstrate encrypted data reaches backend
    """
    try:
        # Check content type
        if not request.is_json:
            logger.warning(f"Received request with non-JSON content type: {request.content_type}")
            return jsonify({"error": "Content-Type must be application/json"}), 400
        
        # Parse incoming JSON payload
        data = request.get_json()
        
        if data is None:
            logger.warning("Received request with no JSON body")
            return jsonify({"error": "No JSON body provided"}), 400
        
        # Log received data with structured format for demo visibility
        logger.info("=" * 60)
        logger.info("BACKEND RECEIVED REQUEST")
        logger.info("=" * 60)
        logger.info(f"Payload: {json.dumps(data, indent=2)}")
        
        # Log individual fields to show encrypted values
        for key, value in data.items():
            # Check if value looks like encrypted data (base64 KMS ciphertext)
            if isinstance(value, str) and value.startswith('AQICA'):
                logger.info(f"[ENCRYPTED FIELD] {key}: {value[:50]}...")
            else:
                logger.info(f"[PLAINTEXT FIELD] {key}: {value}")
        
        logger.info("=" * 60)
        
        # Echo back received data with additional fields
        response = {
            **data,
            "processed": True,
            "backend_message": "Data received and processed successfully"
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
    logger.info("  POST /api/submit - Accept and echo JSON payloads")
    logger.info("  GET  /health     - Health check")
    
    # Run on all interfaces, port 5000
    # Requirements: 3.5 - Run as standalone service behind NGINX
    app.run(host='0.0.0.0', port=5000, debug=False)
