import json

from lib.utils import base64_url_decode


class ClientData:
    def __init__(self, raw):
        client_data = base64_url_decode(raw).decode('utf-8')
        self.json = json.loads(client_data)

    def dump(self):
        return self.json
