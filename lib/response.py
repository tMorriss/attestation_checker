import codecs

from exceptions import FormatException
from lib.attestationObject import AttestationObject
from lib.clientData import ClientData


ATTESTATION_OBJECT = 'attestationObject'
CLIENT_DATA_JSON = 'clientDataJSON'
TRANSPORTS = 'transports'


class Response:
    def __init__(self, json):
        self.json = json

        # validate
        if ATTESTATION_OBJECT not in json:
            raise FormatException(f'response.{ATTESTATION_OBJECT}')
        if CLIENT_DATA_JSON not in json:
            raise FormatException(f'response.{CLIENT_DATA_JSON}')

        self.attestation_object = AttestationObject(json[ATTESTATION_OBJECT])
        self.client_data = ClientData(json[CLIENT_DATA_JSON])
        self.transports = json[TRANSPORTS]

    def dump(self):
        result = {}
        for key in self.json.keys():
            if key == ATTESTATION_OBJECT:
                result[key] = self.attestation_object.dump()
            elif key == CLIENT_DATA_JSON:
                result[key] = self.client_data.dump()
            else:
                value = self.json[key]
                if type(value) is bytes:
                    result[key] = codecs.encode(value, 'hex')
                else:
                    result[key] = value
        return result
