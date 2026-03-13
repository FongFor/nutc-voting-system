import sys
import os
from flask import Flask, jsonify


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from shared.crypto_utils import generate_rsa_keypair

app = Flask(__name__)

VOTER_PRIVATE_KEY = None  # SK_Voter
VOTER_PUBLIC_KEY = None   # PK_Voter

@app.before_request
def initialize_keys():
    global VOTER_PRIVATE_KEY, VOTER_PUBLIC_KEY
    if VOTER_PRIVATE_KEY is None or VOTER_PUBLIC_KEY is None:
        VOTER_PRIVATE_KEY, VOTER_PUBLIC_KEY = generate_rsa_keypair()
        print("[Voter] RSA 金鑰 ok")

@app.route('/')
def home():
    return jsonify({
        "status": "Voter running",
        "public_key": VOTER_PUBLIC_KEY
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)