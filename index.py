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


@app.route('/attestation/result', methods=["POST"])
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


@app.route('/assertion/options', methods=["POST"])
def assertion_options():
    challenge = generate_id(16)

    return json.dumps({
        "statusCode": SUCCESS_CODE,
        "challenge": challenge,
        "rpId": RP_ID,
        "userVerification": "required"
    })


@app.route('/assertion/result', methods=["POST"])
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


@app.route('/apple-app-site-association', methods=["GET"])
def apple_app_site_association():
    return json.dumps({
        "webcredentials":
        {
            "apps": [
                "8C4E2GHE7U.jp.co.yahoo.YAuction",
                "8C4E2GHE7U.jp.co.yahoo.yfinance",
                "8C4E2GHE7U.jp.co.yahoo.YBackup",
                "8C4E2GHE7U.jp.co.yahoo.enterprise.YBackup",
                "8C4E2GHE7U.jp.co.yahoo.yjtrend01",
                "8C4E2GHE7U.jp.co.yahoo.chievision",
                "8C4E2GHE7U.jp.co.yahoo.YNaviApp",
                "8C4E2GHE7U.jp.co.yahoo.realestate.search",
                "8C4E2GHE7U.jp.co.yahoo.BasePlayer",
                "8C4E2GHE7U.jp.co.yahoo.sports.npb.textlive",
                "8C4E2GHE7U.jp.co.yahoo.enterprise.sports.npb.textlive",
                "8C4E2GHE7U.jp.co.yahoo.ios.sports.sportsnavi",
                "8C4E2GHE7U.jp.co.yahoo.enterprise.sports.sportsnavi",
                "8C4E2GHE7U.jp.co.yahoo.wallet.transfer",
                "8C4E2GHE7U.jp.co.yahoo.realtime.buzzalert",
                "8C4E2GHE7U.jp.co.yahoo.emg.alert",
                "8C4E2GHE7U.jp.co.yahoo.transit.app",
                "8C4E2GHE7U.jp.co.yahoo.ymail",
                "8C4E2GHE7U.jp.co.yahoo.enterprise.ymail",
                "8C4E2GHE7U.jp.co.yahoo.Shopping",
                "8C4E2GHE7U.jp.co.yahoo.partner",
                "8C4E2GHE7U.com.cf.petacal",
                "8C4E2GHE7U.jp.co.yahoo.comic01",
                "8C4E2GHE7U.jp.co.yahoo.ebookjapan",
                "8C4E2GHE7U.jp.co.yahoo.ebookjapanyahoo",
                "8C4E2GHE7U.jp.co.yahoo.apppkgcal",
                "8C4E2GHE7U.jp.co.yahoo.ipn.appli",
                "8C4E2GHE7U.jp.co.yahoo.ipn.appli.qa",
                "8C4E2GHE7U.jp.co.yahoo.ipn.appli.staging",
                "8C4E2GHE7U.jp.co.yahoo.ipn.appli.debug",
                "8C4E2GHE7U.jp.co.yahoo.ipn.appli.test",
                "8C4E2GHE7U.jp.co.yahoo.YWeatherApp",
                "8C4E2GHE7U.jp.co.yahoo.mythingsapp",
                "8C4E2GHE7U.jp.co.yahoo.maps",
                "8C4E2GHE7U.jp.co.yahoo.enterprise.maps",
                "8C4E2GHE7U.jp.co.yahoo.mic.maps",
                "8C4E2GHE7U.jp.co.yahoo.YFortuneApp",
                "8C4E2GHE7U.jp.co.yahoo.enterprise.YFortuneApp",
                "8C4E2GHE7U.com.cf.selene",
                "8C4E2GHE7U.jp.co.yahoo.yjotp",
                "8C4E2GHE7U.jp.trilltrill.trill",
                "8C4E2GHE7U.jp.co.yahoo.fleamarket",
                "8C4E2GHE7U.jp.co.yahoo.paypaymall",
                "8C4E2GHE7U.jp.co.yahoo.onseikensaku",
                "8C4E2GHE7U.jp.co.yahoo.premium.yomihodai",
                "8C4E2GHE7U.jp.co.yahoo.enterprise.fleamarket",
                "8C4E2GHE7U.jp.co.yahoo.paypayfleamarket"
            ]
        }
    }
    )


if __name__ == "__main__":
    run_mode = sys.argv[1] if len(sys.argv) > 1 else 'debug'
    app.run(debug=False if run_mode == 'prod' else True, port=8000)
