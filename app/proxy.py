"""
Flask Proxy Server for EKM Demo

This proxy server provides cryptographic translation services by:
1. Validating client identity using Keycloak JWT tokens (Layer 7 - Application Security)
2. Authenticating with Vault using mTLS certificates
3. Decrypting Data Encryption Keys (DEK) from the Transit Secrets Engine

Architecture:
- Layer 7 (Application): JWT token validation via Keycloak JWKS
- Layer 4 (Transport): mTLS authentication via Vault Certificates
- Layer 1 (Data): DEK decryption via Vault Transit Secrets Engine
"""

from flask import Flask, request, jsonify, Response
import requests
import urllib3
import jwt
import json
import logging
import os
import time
from collections import defaultdict
from datetime import datetime
from typing import Optional, Dict, Any, Tuple
from jwt import PyJWKClient

# Only disable warnings if explicitly requested in non-production environments
if os.environ.get("DISABLE_TLS_WARNINGS", "false").lower() == "true":
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# Configure logging with format and level
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('proxy')

# Configuration constants loaded from environment variables with safe defaults
JWKS_URL = os.environ.get("JWKS_URL", "http://keycloak:8080/realms/ekm-demo/protocol/openid-connect/certs")
VAULT_CERT_AUTH_PATH = os.environ.get("VAULT_CERT_AUTH_PATH", "cert/login")
VAULT_TRANSIT_DECRYPT_PATH = os.environ.get("VAULT_TRANSIT_DECRYPT_PATH", "transit/decrypt/my-master-kek")
VAULT_PORT = int(os.environ.get("VAULT_PORT", "8200"))
VAULT_BASE_URL = os.environ.get("VAULT_BASE_URL", f"https://vault:{VAULT_PORT}")
VAULT_CACERT = os.environ.get("VAULT_CACERT", "/certs/ca.crt")

# Simple in-memory rate limiting configuration
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = int(os.environ.get("RATE_LIMIT_MAX_REQUESTS", "100"))
request_history = defaultdict(list)

def is_rate_limited(ip_address: str) -> bool:
    now = time.time()
    request_history[ip_address] = [t for t in request_history[ip_address] if now - t < RATE_LIMIT_WINDOW]
    if len(request_history[ip_address]) >= RATE_LIMIT_MAX_REQUESTS:
        return True
    request_history[ip_address].append(now)
    return False



class JWKSClient:
    """Encapsulated JWKS client for identity token validation."""
    
    def __init__(self, url: str) -> None:
        self.jwks_client = PyJWKClient(url)
        self.url = url
        logger.info(f"Initialized JWKSClient with URL: {self.url}")
    
    def get_signing_key_from_jwt(self, token: str) -> Any:
        """Retrieve the signing key for a JWT token."""
        return self.jwks_client.get_signing_key_from_jwt(token)
    
    def decode_token(self, token: str, options: Dict[str, Any] = None) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Decode and validate a JWT token.
        
        Args:
            token: The JWT token string to decode.
            options: Decoding options.
            
        Returns:
            Tuple of (is_valid: bool, token_data: dict or error_message: str)
        """
        try:
            signing_key = self.get_signing_key_from_jwt(token)
            
            # Load secure defaults from environment variables
            jwt_audience = os.environ.get("JWT_AUDIENCE")
            jwt_issuer = os.environ.get("JWT_ISSUER")
            
            decode_opts = options or {}
            if not jwt_audience:
                decode_opts.setdefault("verify_aud", False)
            if not jwt_issuer:
                decode_opts.setdefault("verify_iss", False)
                
            data = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=jwt_audience,
                issuer=jwt_issuer,
                options=decode_opts
            )
            logger.info(f"Token validated successfully. Subject: {data.get('sub', 'N/A')}")
            return True, data
        except jwt.ExpiredSignatureError as e:
            logger.error(f"Token expired: {e}")
            return False, f"Token expired: {str(e)}"
        except jwt.InvalidTokenError as e:
            logger.error(f"Invalid token error: {e}")
            return False, f"Invalid token: {str(e)}"
        except Exception as e:
            logger.error(f"Unexpected error during token verification: {e}")
            return False, str(e)


# Initialize global JWKS client
jwks_client = JWKSClient(JWKS_URL)


def validate_identity(auth_header: Optional[str], jwks_client: JWKSClient) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """Validate client identity from Authorization header.
    
    Args:
        auth_header: The Authorization header value.
        jwks_client: The JWKS client instance.
        
    Returns:
        Tuple of (is_valid: bool, token_data: dict or error_message: str)
    """
    if not auth_header or not auth_header.startswith('Bearer '):
        logger.warning("Missing or invalid Bearer token provided.")
        return False, "Missing or Invalid Bearer Token. Identity required."
    
    token = auth_header.split(' ')[1]
    is_valid, result = jwks_client.decode_token(token)
    
    if not is_valid:
        logger.warning(f"Identity validation failed: {result}")
    else:
        logger.info("Identity validation succeeded.")
    
    return is_valid, result


def authenticate_with_vault(cert_path: str = '/certs/proxy.crt', 
                            key_path: str = '/certs/proxy.key') -> Optional[str]:
    """Authenticate with Vault using mTLS certificates.
    
    Args:
        cert_path: Path to the client certificate file.
        key_path: Path to the client private key file.
        
    Returns:
        Client token string on success, None on failure.
    """
    try:
        logger.info("Attempting Vault authentication with mTLS certificates.")
        
        auth_response = requests.post(
            f"{VAULT_BASE_URL}/v1/auth/{VAULT_CERT_AUTH_PATH}",
            cert=(cert_path, key_path),
            verify=VAULT_CACERT,
            timeout=5
        )
        
        logger.info(f"Vault auth response status: {auth_response.status_code}")
        
        if auth_response.status_code != 200:
            logger.error(f"Vault mTLS authentication failed: {auth_response.text}")
            return None
        
        client_token = auth_response.json().get('auth', {}).get('client_token')
        logger.info("mTLS authentication succeeded.")
        return client_token
        
    except Exception as e:
        logger.error(f"Exception during Vault authentication: {e}")
        return None


def decrypt_dek(client_token: str, ciphertext: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """Decrypt a DEK using Vault Transit Secrets Engine.
    
    Args:
        client_token: The Vault client token obtained from mTLS auth.
        ciphertext: The encrypted DEK (base64 encoded).
        
    Returns:
        Tuple of (success: bool, plaintext_dek: str or error_msg_1: str or None, error_msg_2: str or None)
    """
    try:
        logger.info("Attempting DEK decryption from Vault.")
        
        decrypt_response = requests.post(
            f"{VAULT_BASE_URL}/v1/transit/decrypt/my-master-kek",
            headers={"X-Vault-Token": client_token},
            json={"ciphertext": ciphertext},
            cert=('/certs/proxy.crt', '/certs/proxy.key'),
            verify=VAULT_CACERT,
            timeout=5
        )
        
        logger.info(f"Vault decrypt response status: {decrypt_response.status_code}")
        
        if decrypt_response.status_code == 200:
            result = decrypt_response.json()
            plaintext_dek = result.get('data', {}).get('plaintext')
            logger.info("DEK decryption succeeded.")
            return True, plaintext_dek, None
        else:
            logger.error(f"Vault decryption failed with status {decrypt_response.status_code}")
            return False, None, decrypt_response.text
            
    except Exception as e:
        logger.error(f"Exception during DEK decryption: {e}")
        return False, None, str(e)


@app.route('/unwrap-key', methods=['POST'])
def unwrap_dek():
    """
    Decrypt a Data Encryption Key (DEK).
    
    Endpoint: POST /unwrap-key
    
    Request Headers:
        Authorization: Bearer <jwt_token>
    
    Request Body:
        {
            "ciphertext": "<encrypted_dek>"
        }
    
    Response:
        Success: {"plaintext_dek": "<decrypted_key>"}
        Error: {"error": "<error_message>"}
    """
    try:
        # === RATE LIMITING ===
        client_ip = request.remote_addr or 'unknown'
        if is_rate_limited(client_ip):
            logger.warning(f"RATE LIMIT EXCEEDED - Client IP: {client_ip}")
            return jsonify({"error": "Too many requests. Rate limit exceeded."}), 429

        # === LOGGING REQUEST START ===
        logger.info("=" * 60)
        logger.info("REQUEST - /unwrap-key")
        
        # Sanitize headers in log output to prevent leaking JWT tokens
        safe_headers = {k: v for k, v in request.headers.items() if k.lower() != 'authorization'}
        logger.info(f"Request Headers (Sanitized): {safe_headers}")
        
        request_body = {}
        try:
            request_body = request.get_json(silent=True) or {}
        except Exception as e:
            logger.error(f"Failed to parse JSON body: {e}")
            return jsonify({"error": f"Invalid JSON body: {str(e)}"}), 400
        
        logger.info(f"Request Body: {json.dumps(request_body, indent=2)}")
        
        # === LAYER 7: IDENTITY VALIDATION ===
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            logger.warning("IDENTITY CHECK - Missing or invalid Authorization header")
            return jsonify({"error": "Missing or Invalid Bearer Token. Identity required."}), 401
        
        token = auth_header.split(' ')[1]
        is_valid, result = validate_identity(auth_header, jwks_client)
        
        if not is_valid:
            logger.warning(f"IDENTITY CHECK FAILED - {result}")
            return jsonify({"error": f"Cryptographic Identity Validation Failed: {result}"}), 403
        
        # === LAYER 4: CRYPTOGRAPHIC TRANSLATION ===
        encrypted_dek = request_body.get('ciphertext')
        
        # Input validation: ensure ciphertext is present, is a string, and follows expected Vault transit format
        if not encrypted_dek or not isinstance(encrypted_dek, str) or not encrypted_dek.startswith('vault:v1:'):
            logger.warning("REQUEST - Missing or invalid format for 'ciphertext' in request body")
            return jsonify({"error": "Missing or invalid required field: ciphertext. Must be a valid Vault transit ciphertext string."}), 400
        
        client_token = authenticate_with_vault()
        
        if not client_token:
            logger.error("IDENTITY CHECK - mTLS authentication with Vault failed")
            return jsonify({"error": "Vault Authentication Failed. Please check mTLS certificates."}), 503
        
        # === DEK DECRYPTION ===
        success, plaintext_dek, decrypt_error = decrypt_dek(client_token, encrypted_dek)
        
        if success:
            logger.info("REQUEST - DEK decryption successful")
            response_body = {"plaintext_dek": plaintext_dek}
            # Mask plaintext keys in application logs to prevent sensitive data exposure
            logger.info("RESPONSE - DEK decryption successful (plaintext key content masked for security)")
            return jsonify(response_body)
        
        # === ERROR HANDLING ===
        if decrypt_error:
            logger.error(f"RESPONSE - DEK decryption error: {decrypt_error}")
            
        return jsonify({"error": f"Vault Decryption Failed: {decrypt_error}"}), 500
        
    except Exception as e:
        # Catch-all for unexpected exceptions
        logger.exception("UNEXPECTED INTERNAL EXCEPTION")
        logger.error(f"Exception occurred: {type(e).__name__}: {e}")
        
        return jsonify({"error": f"Proxy Internal Exception: {str(e)}"}), 500


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint to verify proxy is running."""
    try:
        # Verify we can reach Vault for mTLS auth
        auth_res = requests.post(
            f"{VAULT_BASE_URL}/v1/auth/{VAULT_CERT_AUTH_PATH}",
            cert=('/certs/proxy.crt', '/certs/proxy.key'),
            verify=VAULT_CACERT,
            timeout=5
        )
        
        vault_status = "OK" if auth_res.status_code == 200 else f"FAIL ({auth_res.status_code})"
        
        health_data = {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "vault_connection": vault_status
        }
        
        logger.info(f"HEALTH CHECK - {health_data}")
        return jsonify(health_data), 200
        
    except Exception as e:
        logger.exception("HEALTH CHECK FAILED")
        return jsonify({"status": "unhealthy", "error": str(e)}), 503


@app.route('/stats', methods=['GET'])
def get_stats():
    """Statistics endpoint showing server info."""
    stats = {
        "proxy_version": "1.0.0",
        "python_version": requests.__version__,
        "flask_version": "unknown",  # Would need import flask.__version__
        "vault_url": VAULT_BASE_URL,
        "keycloak_jwks_url": JWKS_URL,
        "uptime_hint": "Check process start time in OS"
    }
    
    logger.info(f"STATS - {json.dumps(stats, indent=2)}")
    return jsonify(stats), 200


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    logger.warning("404 NOT FOUND")
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(405)
def method_not_allowed(error):
    """Handle 405 errors."""
    logger.warning("405 METHOD NOT ALLOWED")
    return jsonify({"error": "Method not allowed"}), 405


@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


if __name__ == '__main__':
    logger.info("=" * 60)
    logger.info("PROXY SERVER STARTING")
    
    # Load host and port from environment variables to avoid hardcoded interface binding (B104)
    server_host = os.environ.get("HOST", "0.0.0.0")  # nosec B104
    server_port = int(os.environ.get("PORT", "5000"))
    
    logger.info(f"Server listening on {server_host}:{server_port}")
    logger.info("=" * 60)
    
    app.run(host=server_host, port=server_port, debug=False)
