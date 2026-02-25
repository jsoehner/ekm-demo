
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
