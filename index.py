import json
import os
import sys

from flask import Flask, render_template, request

from exceptions import FormatException, UnsupportedException
from lib.utils import generate_id
from lib.response import Response

app = Flask(__name__, static_url_path='/fido/static', static_folder='static')

RP_ID = os.environ['RP_ID']
CREDENTIAL_TIMEOUT_MICROSECOND = 30000
ALG_LIST = {'RS256': -257, 'ES256': -7}
SUCCESS_CODE = "2000"


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/attestation/options', methods=["POST"])
def attestation_options():
    challenge = generate_id(16)
    options = {
        "statusCode": SUCCESS_CODE,
        "rp": {
            "id": RP_ID,
            "name": RP_ID
        },
        "user": {
            "id": "test_user",
            "name": "test_user",
            "displayName": "test_user"
        },
        "challenge": challenge,
        "pubKeyCredParams": [],
        "timeout": CREDENTIAL_TIMEOUT_MICROSECOND,
        "excludeCredentials": [],
        "authenticatorSelection": {
            "authenticatorAttachment": "platform",
            "requireResidentKey": True,
            "userVerification": "preferred"
        },
        "attestation": "direct"
    }

    for alg in ALG_LIST.values():
        options["pubKeyCredParams"].append({
            "type": "public-key",
            "alg": alg
        })

    return json.dumps(options)


@app.route('/attestation/result', methods=["POST"])
def attestation_result():
    try:
        attestation = request.json

        # response読み込み
        if 'response' not in attestation:
            raise FormatException("response")
        response = Response(attestation['response'])
        attestation['response'] = response.dump()

        return json.dumps({
            "statusCode": SUCCESS_CODE,
            "attestation": attestation
        })
    except FormatException as e:
        return json.dumps({
            "statusCode": "4000",
            "statusMessage": "Format Error (" + str(e) + ")"
        })
    except UnsupportedException as e:
        return json.dumps({
            "statusCode": "4001",
            "statusMessage": "Unsupported Request (" + str(e) + ")"
        })


if __name__ == "__main__":
    run_mode = sys.argv[1] if len(sys.argv) > 1 else 'debug'
    app.run(debug=False if run_mode == 'prod' else True, port=8000)
