from lib.utils import bytes_to_base64_url


class AuthData:
    def __init__(self, raw):

        self.rpid_hash = raw[0:32]
        self.flags = raw[32:33]
        self.sign_count = int.from_bytes(
            raw[33:37], byteorder='big')
        self.aaguid = raw[37:53].hex()

        credential_id_length = int.from_bytes(
            raw[53:55], byteorder='big')
        self.credential_id = bytes_to_base64_url(
            raw[55:55 + credential_id_length])

    def dump(self):
        return {
            'rpIdHash': self.rpid_hash.hex(),
            'flags': {
                'UP': (1 & int.from_bytes(self.flags, byteorder='big')) == 1,
                'RFU1': (2 & int.from_bytes(self.flags, byteorder='big')) == 2,
                'UV': (4 & int.from_bytes(self.flags, byteorder='big')) == 4,
                'BE': (8 & int.from_bytes(self.flags, byteorder='big')) == 8,
                'BS': (16 & int.from_bytes(self.flags, byteorder='big')) == 16,
                'RFU2': (32 & int.from_bytes(self.flags, byteorder='big')) == 32,
                'AT': (64 & int.from_bytes(self.flags, byteorder='big')) == 64,
                'ED': (128 & int.from_bytes(self.flags, byteorder='big')) == 128,
            },
            'signCount': self.sign_count,
            'aaguid': self.aaguid,
            'credential_id': self.credential_id,
            'public_key': 'public key....'
        }
