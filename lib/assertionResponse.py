from exceptions import FormatException
from lib.clientData import ClientData
from lib.authData import AuthData
from lib.utils import base64_url_decode

AUTHENTICATOR_DATA = 'authenticatorData'
CLIENT_DATA_JSON = 'clientDataJSON'


class AssertionResponse:
    def __init__(self, json):
        self.json = json
        if CLIENT_DATA_JSON not in json:
            raise FormatException(f'response.{CLIENT_DATA_JSON}')
        if AUTHENTICATOR_DATA not in json:
            raise FormatException(f'response.{AUTHENTICATOR_DATA}')

        self.client_data = ClientData(json[CLIENT_DATA_JSON])
        self.authenticator_data = AuthData(base64_url_decode(json[AUTHENTICATOR_DATA]))

    def dump(self):
        result = {}
        for key in self.json.keys():
            if key == AUTHENTICATOR_DATA:
                result[key] = self.authenticator_data.dump()
            elif key == CLIENT_DATA_JSON:
                result[key] = self.client_data.dump()
            else:
                result[key] = self.json[key]
        return result
