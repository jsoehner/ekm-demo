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

    proxy_app = """
from flask import Flask, request, jsonify
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
app = Flask(__name__)

@app.route('/unwrap-key', methods=['POST'])
def unwrap_dek():
    try:
        encrypted_dek = request.json.get('ciphertext')
        
        # 1. Login to Vault via mTLS to get an application token
        auth_res = requests.post(
            "https://vault:8200/v1/auth/cert/login", 
            cert=('/certs/proxy.crt', '/certs/proxy.key'), 
            verify=False,
            timeout=5
        )
        
        if auth_res.status_code != 200:
            return jsonify({"error": f"mTLS Auth Failed: {auth_res.text}"}), 401
            
        client_token = auth_res.json()['auth']['client_token']
        
        # 2. Ask Vault to decrypt the payload. 
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

# --- 5. Smart Polling for Vault ---
def wait_for_vault():
    print(f"{C.CYAN}[*] Polling Vault API for readiness via mTLS...{C.END}")
    tls_args = {"verify": False, "cert": ('certs/proxy.crt', 'certs/proxy.key')}
    
    for _ in range(30):
        try:
            requests.get("https://127.0.0.1:8250/v1/sys/health", timeout=2, **tls_args)
            print(f"{C.GREEN}[+] Vault is online and accepting mTLS connections.{C.END}")
            print(f"{C.CYAN}[*] Waiting 5s for Proxy Python dependencies to finish installing...{C.END}")
            time.sleep(5) 
            return
        except requests.exceptions.ConnectionError:
            time.sleep(1)
    
    print_diagnostic_trace(service_name="vault", error_msg="Connection Refused: Vault API never became responsive.")

# --- 6. Vault Automated Configuration ---
def configure_vault():
    print(f"\n{C.HEADER}{C.BOLD}=== PHASE 4: VAULT EKM CONFIGURATION ==={C.END}")
    vault_url = "https://127.0.0.1:8250"
    tls_args = {"verify": False, "cert": ('certs/proxy.crt', 'certs/proxy.key')}

    try:
        print(f"{C.CYAN}[*] Initializing and Unsealing Vault...{C.END}")
        init_res = requests.put(f"{vault_url}/v1/sys/init", json={"secret_shares": 1, "secret_threshold": 1}, **tls_args)
        if init_res.status_code != 200:
            print(f"{C.YELLOW}[!] Vault is already initialized.{C.END}")
            return
        
        keys = init_res.json()
        root_token = keys["root_token"]
        unseal_key = keys["keys"][0]

        requests.put(f"{vault_url}/v1/sys/unseal", json={"key": unseal_key}, **tls_args)
        headers = {"X-Vault-Token": root_token}

        print(f"{C.CYAN}[*] Mapping Proxy mTLS Certificate to Vault Access Policy...{C.END}")
        requests.post(f"{vault_url}/v1/sys/auth/cert", headers=headers, json={"type": "cert"}, **tls_args)

        policy = """
        path "transit/encrypt/my-master-kek" { capabilities = ["update"] }
        path "transit/decrypt/my-master-kek" { capabilities = ["update"] }
        """
        requests.put(f"{vault_url}/v1/sys/policies/acl/ekm-proxy-policy", headers=headers, json={"policy": policy}, **tls_args)

        with open("certs/proxy.crt", "r") as f:
            proxy_cert = f.read()
        
        cert_payload = {"certificate": proxy_cert, "policies": "ekm-proxy-policy", "name": "ekm-proxy"}
        requests.post(f"{vault_url}/v1/auth/cert/certs/ekm-proxy", headers=headers, json=cert_payload, **tls_args)

        print(f"{C.CYAN}[*] Enabling Transit Engine and Generating the Key Encryption Key (KEK)...{C.END}")
        requests.post(f"{vault_url}/v1/sys/mounts/transit", headers=headers, json={"type": "transit"}, **tls_args)
        requests.post(f"{vault_url}/v1/transit/keys/my-master-kek", headers=headers, **tls_args)
        
        kek_info = requests.get(f"{vault_url}/v1/transit/keys/my-master-kek", headers=headers, **tls_args).json()
        print(f"{C.GREEN}[+] KEK Created Successfully. Vault holds this key tightly in memory.{C.END}")
        print(f"{C.YELLOW}    KEK Name: {kek_info['data']['name']}{C.END}")
        print(f"{C.YELLOW}    KEK Type: {kek_info['data']['type']} (Exportable: {kek_info['data']['exportable']}){C.END}")

    except Exception as e:
        print_diagnostic_trace(service_name="vault", error_msg=f"Vault API Configuration Failed: {e}")

# --- 7. End-to-End Test Execution ---
def run_decryption_test():
    print(f"\n{C.HEADER}{C.BOLD}=== PHASE 5: END-TO-END EKM DECRYPTION TEST ==={C.END}")
    tls_args = {"verify": False, "cert": ('certs/proxy.crt', 'certs/proxy.key')}
    
    # STEP 1: mTLS Authentication
    print(f"{C.CYAN}-> 1. Establishing Zero-Trust Authenticated Session...{C.END}")
    print(f"      {C.BLUE}WHY:{C.END} Before sending any HTTP payload, the proxy establishes a secure TLS tunnel.")
    print(f"           Vault requires the proxy to present its x509 Client Certificate. Without this,")
    print(f"           the TCP connection is instantly dropped. Once verified, Vault issues an API token.")
    
    auth_res = requests.post("https://127.0.0.1:8250/v1/auth/cert/login", **tls_args)
    client_token = auth_res.json()['auth']['client_token']
    print(f"      {C.GREEN}[+] Success: Proxy authenticated via mTLS and received Vault token.{C.END}\n")
    
    # STEP 2: Data Generation
    print(f"{C.CYAN}-> 2. Simulating Application Data Generation...{C.END}")
    print(f"      {C.BLUE}WHAT:{C.END} A vendor application creates a Data Encryption Key (DEK). This is the")
    print(f"            symmetric key that actually locks and unlocks the underlying business data.")
    plaintext_dek_bytes = b"super-secret-vendor-data-key-12345"
    print(f"      {C.GREEN}[Plaintext DEK]: {plaintext_dek_bytes.decode('utf-8')}{C.END}\n")
    
    # STEP 3: Encryption (Wrapping)
    print(f"{C.CYAN}-> 3. Simulating Cloud Storage: Wrapping the DEK...{C.END}")
    print(f"      {C.BLUE}WHY:{C.END} We cannot store the plaintext DEK in the cloud. Instead, we ask our External")
    print(f"           Key Manager (Vault) to 'wrap' (encrypt) this DEK using our master KEK.")
    print(f"           The resulting Ciphertext is what actually gets saved in Azure Storage.")
    
    plaintext_dek_b64 = base64.b64encode(plaintext_dek_bytes).decode('utf-8')
    encrypt_res = requests.post(
        "https://127.0.0.1:8250/v1/transit/encrypt/my-master-kek",
        headers={"X-Vault-Token": client_token},
        json={"plaintext": plaintext_dek_b64},
        **tls_args
    )
    encrypted_dek = encrypt_res.json()['data']['ciphertext']
    print(f"      {C.RED}[Encrypted DEK (Ciphertext)]: {encrypted_dek}{C.END}\n")
    
    # STEP 4: Decryption via Proxy
    print(f"{C.CYAN}-> 4. Azure Workload Requesting Decryption from the external EKM Proxy...{C.END}")
    print(f"      {C.BLUE}WHY:{C.END} A vendor now needs the data. The Azure workload retrieves the RED Ciphertext")
    print(f"           from storage. Because Azure does NOT possess the master KEK, it sends the")
    print(f"           Ciphertext to our Python Proxy. The Proxy securely passes it to Vault.")
    print(f"           Vault unwraps it, and the Proxy securely returns the GREEN Plaintext DEK to Azure.")
    
    try:
        proxy_res = requests.post(
            "http://127.0.0.1:5050/unwrap-key",
            json={"ciphertext": encrypted_dek},
            timeout=10
        )
        
        if proxy_res.status_code == 200:
            decrypted_base64 = proxy_res.json()['plaintext_dek']
            decrypted_raw = base64.b64decode(decrypted_base64).decode('utf-8')
            print(f"      {C.GREEN}[+] SUCCESS! Proxy forwarded the cipher, Vault unwrapped it securely.{C.END}")
            print(f"      {C.GREEN}[Recovered Plaintext DEK]: {decrypted_raw}{C.END}")
        else:
            print(f"      {C.RED}[!] Decryption Failed: {proxy_res.text}{C.END}")
    except Exception as e:
         print(f"      {C.RED}[!] Proxy Communication Error: {e}{C.END}")
         print_diagnostic_trace(service_name="ekm-proxy")

    print(f"\n{C.HEADER}{C.BOLD}========================================================{C.END}\n")

if __name__ == "__main__":
    print(f"{C.BOLD}--- Starting EKM Architecture Deployment (v0.9.3) ---{C.END}")
    generate_mtls_certs()
    write_configs()
    start_infrastructure()
    wait_for_vault()
    configure_vault()
    run_decryption_test()
