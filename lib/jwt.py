import json

from exceptions import FormatException, UnsupportedException
from lib.utils import base64_url_decode


class JWT:
    def __init__(self, text):
        jwt = text.split('.')
        if len(jwt) != 3:
            raise FormatException("jwt")

        self.header = json.loads(base64_url_decode(jwt[0]).decode())
        self.payload = json.loads(base64_url_decode(jwt[1]).decode())

        self.base64_header = jwt[0]
        self.base64_payload = jwt[1]
        self.signature = jwt[2] # base64 url

    def dump(self):
        return {
            'header': self.header,
            'payload': self.payload,
            'signature': self.signature
        }
