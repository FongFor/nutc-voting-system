import sys
import os
from flask import Flask, jsonify


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from shared.crypto_utils import generate_rsa_keypair

app = Flask(__name__)


TA_PRIVATE_KEY = None  # SK_TA
TA_PUBLIC_KEY = None   # PK_TA

@app.before_request
def initialize_keys():
    global TA_PRIVATE_KEY, TA_PUBLIC_KEY
    if TA_PRIVATE_KEY is None or TA_PUBLIC_KEY is None:
        TA_PRIVATE_KEY, TA_PUBLIC_KEY = generate_rsa_keypair()
        print("[TA] OK")

@app.route('/')
def home():
    return jsonify({
        "status": "TA Running",
        "public_key": TA_PUBLIC_KEY
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)