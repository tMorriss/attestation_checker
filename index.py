import json
import os
import sys

from flask import Flask, render_template, request

from exceptions import FormatException, UnsupportedException
from lib.assertion import Assertion
from lib.utils import generate_id
from lib.attestationResponse import AttestationResponse

app = Flask(__name__, static_url_path='/fido/static', static_folder='static')

RP_ID = os.environ['RP_ID'] if 'RP_ID' in os.environ.keys() else 'localhost'
CREDENTIAL_TIMEOUT_MICROSECOND = 30000
ALG_LIST = {'ES256': -7, 'RS256': -257}
SUCCESS_CODE = "2000"


@app.route('/')
def index():
    return render_template('index.html',
                           user_agent=request.user_agent,
                           sec_ch_ua=request.headers.get('sec-ch-ua'),
                           sec_ch_ua_arch=request.headers.get(
                               'sec-ch-ua-arch'),
                           sec_ch_ua_bitness=request.headers.get(
                               'sec-ch-ua-bitness'),
                           sec_ch_ua_full_version_list=request.headers.get(
                               'sec-ch-ua-full-version-list'),
                           sec_ch_ua_full_version=request.headers.get(
                               'sec-ch-ua-full-version'),
                           sec_ch_ua_mobile=request.headers.get(
                               'sec-ch-ua-mobile'),
                           sec_ch_ua_model=request.headers.get(
                               'sec-ch-ua-model'),
                           sec_ch_ua_platform=request.headers.get(
                               'sec-ch-ua-platform'),
                           sec_ch_ua_platform_version=request.headers.get(
                               'sec-ch-ua-platform-version'),
                           sec_ch_prefers_reduced_motion=request.headers.get(
                               'sec-ch-prefers-reduced-motion'),
                           sec_ch_prefers_color_scheme=request.headers.get(
                               'sec-ch-prefers-color-scheme'),
                           device_memory=request.headers.get(
                               'device-memory'),
                           dpr=request.headers.get(
                               'dpr'),
                           width=request.headers.get(
                               'width'),
                           viewport_width=request.headers.get(
                               'viewport-width'),
                           save_data=request.headers.get(
                               'save-data'),
                           downlink=request.headers.get(
                               'downlink'),
                           ect=request.headers.get(
                               'ect'),
                           rtt=request.headers.get(
                               'rtt'),
                           )


@ app.route('/attestation/options', methods=["POST"])
def attestation_options():
    challenge = generate_id(16)
    options = {
        "statusCode": SUCCESS_CODE,
        "rp": {
            "id": RP_ID,
            "name": RP_ID
        },
        "user": {
            "id": "test_user_id",
            "name": "test_user_name",
            "displayName": "test_user_display_name"
        },
        "challenge": challenge,
        "pubKeyCredParams": [],
        "timeout": CREDENTIAL_TIMEOUT_MICROSECOND,
        "excludeCredentials": [],
        # js側で上書きするようにしている
        # "authenticatorSelection": {
        #     "authenticatorAttachment": "platform",
        #     "requireResidentKey": True,
        #     "residentKey": "required",
        #     "userVerification": "required"
        # },
        # "attestation": "direct"
    }

    for alg in ALG_LIST.values():
        options["pubKeyCredParams"].append({
            "type": "public-key",
            "alg": alg
        })

    return json.dumps(options)


@ app.route('/attestation/result', methods=["POST"])
def attestation_result():
    try:
        attestation = request.json

        # response読み込み
        if 'response' not in attestation:
            raise FormatException("response")
        response = AttestationResponse(attestation['response'])
        attestation['response'] = response.dump()

        return json.dumps({
            "statusCode": SUCCESS_CODE,
            "attestation": attestation,
            "credential_id": response.attestation_object.auth_data.credential_id,
            "transports": ','.join(response.transports),
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


@ app.route('/assertion/options', methods=["POST"])
def assertion_options():
    challenge = generate_id(16)

    return json.dumps({
        "statusCode": SUCCESS_CODE,
        "challenge": challenge,
        "rpId": RP_ID,
        "userVerification": "required"
    })


@ app.route('/assertion/result', methods=["POST"])
def assertion_result():
    try:
        assertion = Assertion(request.json)

        return json.dumps({
            "statusCode": SUCCESS_CODE,
            "assertion": assertion.dump()
        })
    except FormatException as e:
        return json.dumps({
            "statusCode": "4000",
            "statusMessage": "Format Error (" + str(e) + ")"
        })


if __name__ == "__main__":
    run_mode = sys.argv[1] if len(sys.argv) > 1 else 'debug'
    app.run(debug=False if run_mode == 'prod' else True, port=8000)
