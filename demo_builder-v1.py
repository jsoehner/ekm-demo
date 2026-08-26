import subprocess
import time
import requests
import os
import shutil
import urllib3
import sys
import base64

# Suppress insecure request warnings for local self-signed mTLS connections
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- ANSI Color Codes for Educational Console Output ---
class C:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

# --- 1. Diagnostics & Tracing Engine ---
def print_diagnostic_trace(service_name=None, error_msg=None):
    print(f"\n{C.RED}{C.BOLD}" + "="*60)
    print(" 🚨 DIAGNOSTIC TRACE TRIGGERED 🚨")
    print("="*60 + f"{C.END}")
    if error_msg:
        print(f"{C.RED}Exception Caught: {error_msg}\n{C.END}")
    
    print("--- 1. Container Status ---")
    subprocess.run("docker compose ps", shell=True)
    
    if service_name:
        print(f"\n--- 2. Console Output (Logs) for: {service_name} ---")
        subprocess.run(f"docker compose logs --tail 50 {service_name}", shell=True)
    else:
        print("\n--- 2. Console Output (Logs) for ALL services ---")
        subprocess.run("docker compose logs --tail 20", shell=True)
    
    sys.exit(1)

# --- 2. PKI & mTLS Generation ---
def generate_mtls_certs():
    print(f"\n{C.HEADER}{C.BOLD}=== PHASE 1: PKI & mTLS GENERATION ==={C.END}")
    print(f"{C.CYAN}[*] Generating self-signed Root CA and Server/Client certificates...{C.END}")
    os.makedirs("certs", exist_ok=True)
    try:
        subprocess.run("openssl req -x509 -newkey rsa:4096 -keyout certs/ca.key -out certs/ca.crt -days 365 -nodes -subj '/CN=DemoRootCA'", shell=True, check=True, stderr=subprocess.DEVNULL)
        subprocess.run("openssl req -newkey rsa:2048 -keyout certs/vault.key -out certs/vault.csr -nodes -subj '/CN=vault' -addext 'subjectAltName = DNS:vault,DNS:localhost,IP:127.0.0.1'", shell=True, check=True, stderr=subprocess.DEVNULL)
        subprocess.run("openssl x509 -req -in certs/vault.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/vault.crt -days 365 -copy_extensions copy", shell=True, check=True, stderr=subprocess.DEVNULL)
        subprocess.run("openssl req -newkey rsa:2048 -keyout certs/proxy.key -out certs/proxy.csr -nodes -subj '/CN=ekm-proxy'", shell=True, check=True, stderr=subprocess.DEVNULL)
        subprocess.run("openssl x509 -req -in certs/proxy.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/proxy.crt -days 365", shell=True, check=True, stderr=subprocess.DEVNULL)
        
        print(f"{C.CYAN}[*] Validating Proxy Client Certificate (Used for mTLS authentication):{C.END}")
        cert_info = subprocess.run("openssl x509 -in certs/proxy.crt -noout -subject -issuer -dates", shell=True, capture_output=True, text=True).stdout
        print(f"{C.YELLOW}{cert_info.strip()}{C.END}")
        
    except subprocess.CalledProcessError as e:
        print_diagnostic_trace(error_msg=f"OpenSSL failed: {e}")

# --- 3. Configuration Generation ---
def write_configs():
    print(f"\n{C.HEADER}{C.BOLD}=== PHASE 2: CONFIGURATION & DOCKER BUILD ==={C.END}")
    print(f"{C.CYAN}[*] Writing isolated Vault HCL, Docker Compose, and Proxy Python app...{C.END}")
    
    if os.path.exists("config"):
        shutil.rmtree("config")
    os.makedirs("config", exist_ok=True)
    os.makedirs("app", exist_ok=True)
    
    vault_config = """
    listener "tcp" {
      address       = "0.0.0.0:8200"
      tls_cert_file = "/vault/certs/vault.crt"
      tls_key_file  = "/vault/certs/vault.key"
      tls_client_ca_file = "/vault/certs/ca.crt"
      tls_require_and_verify_client_cert = "true"
    }
    storage "inmem" {}
    disable_mlock = true
    ui = true
    """
    with open("config/vault.hcl", "w") as f:
        f.write(vault_config)

    docker_compose = """
services:
  keycloak:
    image: quay.io/keycloak/keycloak:latest
    command: start-dev
    environment:
      KC_DB: dev-file
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: admin
    ports: ["8080:8080"]
  
  vault:
    image: hashicorp/vault:latest
    entrypoint: ["vault", "server", "-config=/vault/config/vault.hcl"]
    cap_add: ["IPC_LOCK"]
    ports: ["8250:8200"] 
    volumes:
      - ./config:/vault/config
      - ./certs:/vault/certs

  ekm-proxy:
    image: python:3.9-slim
    command: sh -c "pip install flask requests pyjwt cryptography gunicorn && gunicorn -b 0.0.0.0:5000 --chdir /app proxy:app"
    volumes:
      - ./app:/app
      - ./certs:/certs
    ports: ["5050:5000"]
"""
    with open("docker-compose.yml", "w") as f:
        f.write(docker_compose)

    # VERSION 1.0: Proxy now validates Layer-7 Identity via JWT before attempting Layer-4 Decryption
    proxy_app = """\"\"\"
Flask Proxy Server for EKM Demo

This proxy server provides cryptographic translation services by:
1. Validating client identity using Keycloak JWT tokens (Layer 7 - Application Security)
2. Authenticating with Vault using mTLS certificates
3. Decrypting Data Encryption Keys (DEK) from the Transit Secrets Engine

Architecture:
- Layer 7 (Application): JWT token validation via Keycloak JWKS
- Layer 4 (Transport): mTLS authentication via Vault Certificates
- Layer 1 (Data): DEK decryption via Vault Transit Secrets Engine
\"\"\"

from flask import Flask, request, jsonify, Response
import requests
import urllib3
import jwt
import json
import logging
from datetime import datetime
from typing import Optional, Dict, Any, Tuple
from jwt import PyJWKClient

# Disable InsecureRequestWarning for development/testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# Configure logging with format and level
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('proxy')

# Configuration constants
JWKS_URL = "http://keycloak:8080/realms/ekm-demo/protocol/openid-connect/certs"
VAULT_CERT_AUTH_PATH = "cert/login"
VAULT_TRANSIT_DECRYPT_PATH = "transit/decrypt/my-master-kek"
VAULT_PORT = 8200
VAULT_BASE_URL = f"https://vault:{VAULT_PORT}"
VAULT_CACERT = "/certs/ca.crt"


class JWKSClient:
    \"\"\"Encapsulated JWKS client for identity token validation.\"\"\"
    
    def __init__(self, url: str) -> None:
        self.jwks_client = PyJWKClient(url)
        self.url = url
        logger.info(f"Initialized JWKSClient with URL: {self.url}")
    
    def get_signing_key_from_jwt(self, token: str) -> Any:
        \"\"\"Retrieve the signing key for a JWT token.\"\"\"
        return self.jwks_client.get_signing_key_from_jwt(token)
    
    def decode_token(self, token: str, options: Dict[str, Any] = None) -> Tuple[bool, Optional[Dict[str, Any]]]:
        \"\"\"Decode and validate a JWT token.
        
        Args:
            token: The JWT token string to decode.
            options: Decoding options (e.g., verify_aud=False for simplified demo).
            
        Returns:
            Tuple of (is_valid: bool, token_data: dict or error_message: str)
        \"\"\"
        try:
            signing_key = self.get_signing_key_from_jwt(token)
            data = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                options=options or {"verify_aud": False}  # Simplified for demo purposes
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
    \"\"\"Validate client identity from Authorization header.
    
    Args:
        auth_header: The Authorization header value.
        jwks_client: The JWKS client instance.
        
    Returns:
        Tuple of (is_valid: bool, token_data: dict or error_message: str)
    \"\"\"
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
    \"\"\"Authenticate with Vault using mTLS certificates.
    
    Args:
        cert_path: Path to the client certificate file.
        key_path: Path to the client private key file.
        
    Returns:
        Client token string on success, None on failure.
    \"\"\"
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
    \"\"\"Decrypt a DEK using Vault Transit Secrets Engine.
    
    Args:
        client_token: The Vault client token obtained from mTLS auth.
        ciphertext: The encrypted DEK (base64 encoded).
        
    Returns:
        Tuple of (success: bool, plaintext_dek: str or error_msg_1: str or None, error_msg_2: str or None)
    \"\"\"
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
    \"\"\"
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
    \"\"\"
    try:
        # === LOGGING REQUEST START ===
        logger.info("=" * 60)
        logger.info("REQUEST - /unwrap-key")
        logger.info(f"Request Headers: {dict(request.headers)}")
        
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
        
        if not encrypted_dek:
            logger.warning("REQUEST - Missing 'ciphertext' in request body")
            return jsonify({"error": "Missing required field: ciphertext"}), 400
        
        client_token = authenticate_with_vault()
        
        if not client_token:
            logger.error("IDENTITY CHECK - mTLS authentication with Vault failed")
            # Include detailed auth error info in log but not in response
            return jsonify({"error": "Vault Authentication Failed. Please check mTLS certificates."}), 503
        
        # === DEK DECRYPTION ===
        success, plaintext_dek, decrypt_error = decrypt_dek(client_token, encrypted_dek)
        
        if success:
            logger.info("REQUEST - DEK decryption successful")
            response_body = {"plaintext_dek": plaintext_dek}
            logger.info(f"RESPONSE - {json.dumps(response_body, indent=2)}")
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
    \"\"\"Health check endpoint to verify proxy is running.\"\"\"
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
    \"\"\"Statistics endpoint showing server info.\"\"\"
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
    \"\"\"Handle 404 errors.\"\"\"
    logger.warning("404 NOT FOUND")
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(405)
def method_not_allowed(error):
    \"\"\"Handle 405 errors.\"\"\"
    logger.warning("405 METHOD NOT ALLOWED")
    return jsonify({"error": "Method not allowed"}), 405


if __name__ == '__main__':
    logger.info("=" * 60)
    logger.info("PROXY SERVER STARTING")
    logger.info(f"Server listening on 0.0.0.0:5000")
    logger.info("=" * 60)
    
    app.run(host='0.0.0.0', port=5000, debug=False)
"""
    with open("app/proxy.py", "w") as f:
        f.write(proxy_app)

# --- 4. Infrastructure Deployment ---
def start_infrastructure():
    print(f"\n{C.HEADER}{C.BOLD}=== PHASE 3: CONTAINER DEPLOYMENT ==={C.END}")
    print(f"{C.CYAN}[*] Tearing down existing infrastructure to ensure clean state...{C.END}")
    subprocess.run("docker compose down -v --remove-orphans", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    
    print(f"{C.CYAN}[*] Starting Docker containers...{C.END}")
    try:
        subprocess.run("docker compose up -d", shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"{C.GREEN}[+] Containers launched successfully.{C.END}")
    except subprocess.CalledProcessError as e:
        print_diagnostic_trace(error_msg="Docker Compose failed to start the containers.")

# --- 5. Smart Polling ---
def wait_for_services():
    print(f"\n{C.HEADER}{C.BOLD}=== PHASE 4: INFRASTRUCTURE READINESS ==={C.END}")
    
    # 1. Vault Polling
    print(f"{C.CYAN}[*] Polling Vault API for readiness via mTLS...{C.END}")
    tls_args = {"verify": False, "cert": ('certs/proxy.crt', 'certs/proxy.key')}
    vault_ready = False
    for _ in range(30):
        try:
            requests.get("https://127.0.0.1:8250/v1/sys/health", timeout=2, **tls_args)
            print(f"{C.GREEN}[+] Vault is online and accepting mTLS connections.{C.END}")
            vault_ready = True
            break
        except requests.exceptions.ConnectionError:
            time.sleep(1)
    if not vault_ready:
        print_diagnostic_trace(service_name="vault", error_msg="Vault API never became responsive.")

    # 2. Keycloak Polling (Takes longer to boot)
    print(f"{C.CYAN}[*] Polling Keycloak Identity Provider for readiness...{C.END}")
    keycloak_ready = False
    for _ in range(60):
        try:
            res = requests.get("http://127.0.0.1:8080/realms/master", timeout=2)
            if res.status_code == 200:
                print(f"{C.GREEN}[+] Keycloak is online.{C.END}")
                keycloak_ready = True
                break
        except requests.exceptions.ConnectionError:
            time.sleep(2)
    if not keycloak_ready:
        print_diagnostic_trace(service_name="keycloak", error_msg="Keycloak never became responsive.")

    print(f"{C.CYAN}[*] Waiting 5s for Proxy Python dependencies to finish installing...{C.END}")
    time.sleep(5)

# --- 6. Identity & Cryptography Configuration ---
def configure_environment():
    print(f"\n{C.HEADER}{C.BOLD}=== PHASE 5: OIDC & EKM CONFIGURATION ==={C.END}")
    
    # --- KEYCLOAK (OIDC) CONFIGURATION ---
    print(f"{C.CYAN}[*] Configuring Keycloak (Simulating Microsoft Entra ID)...{C.END}")
    try:
        # Get Admin Token
        token_res = requests.post(
            "http://127.0.0.1:8080/realms/master/protocol/openid-connect/token",
            data={"client_id": "admin-cli", "username": "admin", "password": "admin", "grant_type": "password"}
        )
        kc_token = token_res.json()["access_token"]
        kc_headers = {"Authorization": f"Bearer {kc_token}", "Content-Type": "application/json"}

        # Create Realm
        requests.post("http://127.0.0.1:8080/admin/realms", headers=kc_headers, json={"realm": "ekm-demo", "enabled": True})
        
        # Create Service Principal Client (Azure Workload)
        client_payload = {
            "clientId": "azure-workload",
            "enabled": True,
            "serviceAccountsEnabled": True, # Client Credentials Grant
            "publicClient": False,
            "secret": "demo-client-secret-123"
        }
        requests.post("http://127.0.0.1:8080/admin/realms/ekm-demo/clients", headers=kc_headers, json=client_payload)
        print(f"{C.GREEN}[+] Identity Provider Configured: Realm 'ekm-demo' and Client 'azure-workload' created.{C.END}")
    except Exception as e:
        print_diagnostic_trace(service_name="keycloak", error_msg=f"Keycloak Config Failed: {e}")

    # --- VAULT (EKM) CONFIGURATION ---
    print(f"{C.CYAN}[*] Configuring Vault (Hardware Security Module Mock)...{C.END}")
    vault_url = "https://127.0.0.1:8250"
    tls_args = {"verify": False, "cert": ('certs/proxy.crt', 'certs/proxy.key')}

    try:
        init_res = requests.put(f"{vault_url}/v1/sys/init", json={"secret_shares": 1, "secret_threshold": 1}, **tls_args)
        if init_res.status_code == 200:
            keys = init_res.json()
            requests.put(f"{vault_url}/v1/sys/unseal", json={"key": keys["keys"][0]}, **tls_args)
            headers = {"X-Vault-Token": keys["root_token"]}

            requests.post(f"{vault_url}/v1/sys/auth/cert", headers=headers, json={"type": "cert"}, **tls_args)
            
            policy = 'path "transit/encrypt/my-master-kek" { capabilities = ["update"] }\npath "transit/decrypt/my-master-kek" { capabilities = ["update"] }'
            requests.put(f"{vault_url}/v1/sys/policies/acl/ekm-proxy-policy", headers=headers, json={"policy": policy}, **tls_args)

            with open("certs/proxy.crt", "r") as f: proxy_cert = f.read()
            requests.post(f"{vault_url}/v1/auth/cert/certs/ekm-proxy", headers=headers, json={"certificate": proxy_cert, "policies": "ekm-proxy-policy", "name": "ekm-proxy"}, **tls_args)

            requests.post(f"{vault_url}/v1/sys/mounts/transit", headers=headers, json={"type": "transit"}, **tls_args)
            requests.post(f"{vault_url}/v1/transit/keys/my-master-kek", headers=headers, **tls_args)
            
            kek_info = requests.get(f"{vault_url}/v1/transit/keys/my-master-kek", headers=headers, **tls_args).json()
            print(f"{C.GREEN}[+] KEK Created Successfully. Vault holds this key tightly in memory.{C.END}")
            print(f"{C.YELLOW}    KEK Name: {kek_info['data']['name']}{C.END}")
    except Exception as e:
        print_diagnostic_trace(service_name="vault", error_msg=f"Vault Config Failed: {e}")

# --- 7. End-to-End Test Execution ---
def run_decryption_test():
    print(f"\n{C.HEADER}{C.BOLD}=== PHASE 6: END-TO-END EKM DECRYPTION TEST (v1.0) ==={C.END}")
    tls_args = {"verify": False, "cert": ('certs/proxy.crt', 'certs/proxy.key')}
    
    # 1. Generate Fake Storage Data
    print(f"{C.CYAN}-> 1. Simulating Storage: Wrapping the Application Data Key...{C.END}")
    auth_res = requests.post("https://127.0.0.1:8250/v1/auth/cert/login", **tls_args)
    client_token = auth_res.json()['auth']['client_token']
    
    plaintext_dek_bytes = b"super-secret-vendor-data-key-12345"
    plaintext_dek_b64 = base64.b64encode(plaintext_dek_bytes).decode('utf-8')
    encrypt_res = requests.post(
        "https://127.0.0.1:8250/v1/transit/encrypt/my-master-kek",
        headers={"X-Vault-Token": client_token},
        json={"plaintext": plaintext_dek_b64},
        **tls_args
    )
    encrypted_dek = encrypt_res.json()['data']['ciphertext']
    print(f"      {C.RED}[Encrypted DEK (Ciphertext)]: {encrypted_dek}{C.END}\n")

    # 2. Acquire Identity Token (The Entra ID Service Principal Simulation)
    print(f"{C.CYAN}-> 2. Acquiring Identity Token from Identity Provider (Keycloak)...{C.END}")
    print(f"      {C.BLUE}WHY:{C.END} The Azure Workload must prove *who* it is before requesting decryption.")
    print(f"           It uses a Client Credentials grant to obtain a JWT.")
    token_payload = {
        "client_id": "azure-workload",
        "client_secret": "demo-client-secret-123",
        "grant_type": "client_credentials"
    }
    oidc_res = requests.post("http://127.0.0.1:8080/realms/ekm-demo/protocol/openid-connect/token", data=token_payload)
    workload_jwt = oidc_res.json()["access_token"]
    print(f"      {C.YELLOW}[JWT Acquired]: {workload_jwt[:40]}... (truncated){C.END}\n")
    
    # 3. Request Decryption
    print(f"{C.CYAN}-> 3. Requesting Decryption from the EKM Proxy via API Gateway...{C.END}")
    print(f"      {C.BLUE}WHY:{C.END} The Proxy receives the encrypted data AND the JWT. It validates the JWT")
    print(f"           cryptographically against Keycloak. Only if the identity is valid will it")
    print(f"           use its mTLS certificate to ask Vault to decrypt the payload.")
    
    try:
        proxy_res = requests.post(
            "http://127.0.0.1:5050/unwrap-key",
            headers={"Authorization": f"Bearer {workload_jwt}"}, # Supplying the Identity Badge
            json={"ciphertext": encrypted_dek},
            timeout=10
        )
        
        if proxy_res.status_code == 200:
            decrypted_base64 = proxy_res.json()['plaintext_dek']
            decrypted_raw = base64.b64decode(decrypted_base64).decode('utf-8')
            print(f"      {C.GREEN}[+] SUCCESS! Proxy validated OIDC token, forwarded cipher, and unwrapped the key.{C.END}")
            print(f"      {C.GREEN}[Recovered Plaintext DEK]: {decrypted_raw}{C.END}")
        else:
            print(f"      {C.RED}[!] Decryption Failed: {proxy_res.text}{C.END}")
    except Exception as e:
         print(f"      {C.RED}[!] Proxy Communication Error: {e}{C.END}")
         print_diagnostic_trace(service_name="ekm-proxy")

    print(f"\n{C.HEADER}{C.BOLD}========================================================{C.END}\n")

if __name__ == "__main__":
    print(f"{C.BOLD}--- Starting EKM Architecture Deployment (v1.0) ---{C.END}")
    generate_mtls_certs()
    write_configs()
    start_infrastructure()
    wait_for_services()
    configure_environment()
    run_decryption_test()
