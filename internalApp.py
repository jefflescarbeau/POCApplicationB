import os
import requests
import jwt
from flask import Flask, jsonify, request
from functools import wraps

app = Flask(__name__)

# --- CONFIGURATION - SET THESE AS ENVIRONMENT VARIABLES IN RENDER ---
SALESFORCE_URL = os.environ.get('SALESFORCE_URL') # e.g., https://your-domain.my.salesforce.com
AUDIENCE = os.environ.get('AUDIENCE')             # Your Connected App's Consumer Key

# Simple in-memory cache for Salesforce's public keys
SALESFORCE_PUBLIC_KEYS = {}

def get_salesforce_public_keys():
    """Fetches and caches Salesforce's public keys for JWT validation."""
    global SALESFORCE_PUBLIC_KEYS
    if SALESFORCE_PUBLIC_KEYS:
        return SALESFORCE_PUBLIC_KEYS
        
    print("Fetching Salesforce public keys...")
    jwks_url = f"{SALESFORCE_URL}/id/keys"
    try:
        response = requests.get(jwks_url)
        response.raise_for_status()
        jwks = response.json()
        
        # The public keys are under the 'keys' list
        for key in jwks.get('keys', []):
            SALESFORCE_PUBLIC_KEYS[key['kid']] = jwt.algorithms.RSAAlgorithm.from_jwk(key)
        
        return SALESFORCE_PUBLIC_KEYS
    except Exception as e:
        print(f"Error fetching SFDC public keys: {e}")
        return {}
        
get_salesforce_public_keys()  # Initial fetch

def token_required(f):
    """A decorator to protect routes by validating the JWT."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Authorization header is missing or invalid"}), 401

        token = auth_header.split(' ')[1]
        
        try:
            # 1. Get the key ID (kid) from the token header without verifying
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header['kid']
            
            # 2. Fetch the corresponding public key
            public_keys = get_salesforce_public_keys()
            public_key = public_keys.get(kid)
            
            if not public_key:
                return jsonify({"error": "Public key not found for token"}), 401
            
            # 3. Decode and validate the token
            jwt.decode(
                token,
                key=public_key,
                algorithms=['RS256'],
                audience=AUDIENCE, # Validates the 'aud' claim
                issuer=SALESFORCE_URL # Validates the 'iss' claim
            )
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError as e:
            return jsonify({"error": "Token is invalid", "details": str(e)}), 401
        
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def home():
    return "Application B: Internal API. Ready to receive requests."

@app.route('/api/data')
@token_required
def get_protected_data():
    """This is a protected endpoint that requires a valid token."""
    return jsonify({
        "message": "Access Granted!",
        "data": {
            "productId": "XYZ-123",
            "productName": "Super Widget",
            "inventory": 42
        }
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))