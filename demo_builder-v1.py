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
        subprocess.run("openssl req -newkey rsa:2048 -keyout certs/vault.key -out certs/vault.csr -nodes -subj '/CN=vault'", shell=True, check=True, stderr=subprocess.DEVNULL)
        subprocess.run("openssl x509 -req -in certs/vault.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/vault.crt -days 365", shell=True, check=True, stderr=subprocess.DEVNULL)
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
    command: sh -c "pip install flask requests pyjwt cryptography && python /app/proxy.py"
    volumes:
      - ./app:/app
      - ./certs:/certs
    ports: ["5050:5000"]
"""
    with open("docker-compose.yml", "w") as f:
        f.write(docker_compose)

    # VERSION 1.0: Proxy now validates Layer-7 Identity via JWT before attempting Layer-4 Decryption
    proxy_app = """
from flask import Flask, request, jsonify
import requests
import urllib3
import jwt
from jwt import PyJWKClient

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
app = Flask(__name__)

# Keycloak JWKS Endpoint (Public Keys for Signature Validation)
JWKS_URL = "http://keycloak:8080/realms/ekm-demo/protocol/openid-connect/certs"
jwks_client = PyJWKClient(JWKS_URL)

def verify_identity_token(token):
    try:
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        data = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            options={"verify_aud": False} # Simplified for demo purposes
        )
        return True, data
    except Exception as e:
        return False, str(e)

@app.route('/unwrap-key', methods=['POST'])
def unwrap_dek():
    try:
        # --- LAYER 7: IDENTITY VALIDATION ---
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Missing or Invalid Bearer Token. Identity required."}), 401
            
        token = auth_header.split(' ')[1]
        is_valid, token_data = verify_identity_token(token)
        
        if not is_valid:
            return jsonify({"error": f"Cryptographic Identity Validation Failed: {token_data}"}), 403
            
        # --- LAYER 4: CRYPTOGRAPHIC TRANSLATION ---
        encrypted_dek = request.json.get('ciphertext')
        
        auth_res = requests.post(
            "https://vault:8200/v1/auth/cert/login", 
            cert=('/certs/proxy.crt', '/certs/proxy.key'), 
            verify=False,
            timeout=5
        )
        
        if auth_res.status_code != 200:
            return jsonify({"error": f"mTLS Auth Failed: {auth_res.text}"}), 401
            
        client_token = auth_res.json()['auth']['client_token']
        
        unwrap_res = requests.post(
            "https://vault:8200/v1/transit/decrypt/my-master-kek", 
            headers={"X-Vault-Token": client_token}, 
            json={"ciphertext": encrypted_dek}, 
            cert=('/certs/proxy.crt', '/certs/proxy.key'),
            verify=False,
            timeout=5
        )
        
        if unwrap_res.status_code == 200:
            return jsonify({"plaintext_dek": unwrap_res.json()["data"]["plaintext"]})
            
        return jsonify({"error": f"Vault Decryption Failed: {unwrap_res.text}"}), 500
        
    except Exception as e:
        return jsonify({"error": f"Proxy Internal Exception: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
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
