import sys
import os
from flask import Flask, jsonify


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from shared.crypto_utils import generate_rsa_keypair

app = Flask(__name__)

TPA_PRIVATE_KEY = None  # SK_TPA
TPA_PUBLIC_KEY = None   # PK_TPA

@app.before_request
def initialize_keys():
    global TPA_PRIVATE_KEY, TPA_PUBLIC_KEY
    if TPA_PRIVATE_KEY is None or TPA_PUBLIC_KEY is None:
        TPA_PRIVATE_KEY, TPA_PUBLIC_KEY = generate_rsa_keypair()
        print("[TPA] RSA ok")

@app.route('/')
def home():
    return jsonify({
        "status": "TPA running",
        "public_key": TPA_PUBLIC_KEY
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)