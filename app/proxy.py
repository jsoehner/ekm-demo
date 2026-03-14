
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
