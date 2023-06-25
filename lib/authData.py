from lib.publicKey import PublicKey
from lib.utils import bytes_to_base64_url


class AuthData:
    def __init__(self, raw):

        self.rpid_hash = raw[0:32]
        self.flags = raw[32:33]
        self.sign_count = int.from_bytes(
            raw[33:37], byteorder='big')
        self.aaguid = raw[37:53].hex() if len(raw) > 37 else None

        credential_id_length = int.from_bytes(
            raw[53:55], byteorder='big')
        self.credential_id = bytes_to_base64_url(
            raw[55:55 + credential_id_length]) if credential_id_length > 0 else None
        raw_public_key = raw[55 + credential_id_length:]
        self.pub_key = PublicKey(raw_public_key) if len(raw_public_key) > 0 else None

    def dump(self):
        result = {
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
        }
        attested_credential_data = {}
        if self.aaguid is not None:
            attested_credential_data['aaguid'] = self.aaguid
        if self.credential_id is not None:
            attested_credential_data['credential_id'] = self.credential_id
        if self.pub_key is not None:
            attested_credential_data['public_key'] = self.pub_key.dump()

        if len(attested_credential_data.keys()) > 0:
            result['attestedCredentialData'] = attested_credential_data

        return result
