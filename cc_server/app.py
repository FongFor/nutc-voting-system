import sys
import os
from flask import Flask, jsonify


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from shared.crypto_utils import generate_rsa_keypair

app = Flask(__name__)


CC_PRIVATE_KEY = None  # SK_CC
CC_PUBLIC_KEY = None   # PK_CC

@app.before_request
def initialize_keys():
    global CC_PRIVATE_KEY, CC_PUBLIC_KEY
    if CC_PRIVATE_KEY is None or CC_PUBLIC_KEY is None:
        CC_PRIVATE_KEY, CC_PUBLIC_KEY = generate_rsa_keypair()
        print("[CC] RSA 金鑰 ok")

@app.route('/')
def home():
    return jsonify({
        "status": "CC running",
        "public_key": CC_PUBLIC_KEY
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)