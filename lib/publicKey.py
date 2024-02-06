import cbor2

from exceptions import FormatException, UnsupportedException

ALG_LIST = {'ES256': -7, 'RS256': -257}
KTY_LIST = {'EC2': 2, 'RSA': 3}
EC_KEYS = {1: 'P-256', 2: 'P-384', 3: 'P-521',
           4: 'X25519', 5: 'X448', 6: 'Ed25519', 7: 'Ed448'}


class PublicKey:
    def __init__(self, raw):
        pkey = cbor2.loads(raw)
        if pkey.keys() <= {1, 3}:
            raise FormatException("pkey")

        self.pkey = pkey

    def dump(self):
        if self.pkey[1] == KTY_LIST['RSA'] and self.pkey[3] == ALG_LIST['RS256']:
            return {
                1: self.pkey[1],
                3: self.pkey[3],
                'n': int.from_bytes(self.pkey[-1], byteorder='big'),
                'e': int.from_bytes(self.pkey[-2], byteorder='big')
            }
        elif self.pkey[1] == KTY_LIST['EC2'] and self.pkey[3] == ALG_LIST['ES256']:
            return {
                1: self.pkey[1],
                3: self.pkey[3],
                'curve': EC_KEYS[self.pkey[-1]],
                'x': int.from_bytes(self.pkey[-2], byteorder='big'),
                'y': int.from_bytes(self.pkey[-3], byteorder='big')
            }
        else:
            raise UnsupportedException(
                f'pubKey alg: 1={self.pkey[1]}, 3={self.pkey[3]}')
