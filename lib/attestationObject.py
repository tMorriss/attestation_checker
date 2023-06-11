import cbor2

from exceptions import FormatException, UnsupportedException
from lib.attestationStatement import AndroidSafetyNet, Apple, NoneFmt, Packed, Tpm
from lib.authData import AuthData
from lib.utils import base64_url_decode

FMT = 'fmt'
ATT_STMT = 'attStmt'
AUTH_DATA = 'authData'


class AttestationObject:
    def __init__(self, raw):
        self.cbor = cbor2.loads(base64_url_decode(raw))

        # validate
        if FMT not in self.cbor:
            raise FormatException(f'attestationObject.{FMT}')
        if ATT_STMT not in self.cbor:
            raise FormatException(f'attestationObject.{ATT_STMT}')
        if AUTH_DATA not in self.cbor:
            raise FormatException(f'attestationObject.{AUTH_DATA}')

        self.att_stmt = self.get_att_stmt(self.cbor[FMT], self.cbor[ATT_STMT])
        self.auth_data = AuthData(self.cbor[AUTH_DATA])

    def get_att_stmt(self, fmt, att_stmt):
        if fmt == 'none':
            return NoneFmt(att_stmt)
        elif fmt == 'packed':
            return Packed(att_stmt)
        elif fmt == 'android-safetynet':
            return AndroidSafetyNet(att_stmt)
        elif fmt == 'apple':
            return Apple(att_stmt)
        if fmt == 'tpm':
            return Tpm(att_stmt)
        else:
            raise UnsupportedException(f'attestationObject.{FMT}={fmt}')

    def dump(self):
        result = {}
        for key in self.cbor.keys():
            if key == ATT_STMT:
                result[key] = self.att_stmt.dump()
            elif key == AUTH_DATA:
                result[key] = self.auth_data.dump()
            else:
                value = self.cbor[key]
                if type(value) is bytes:
                    result[key] = value.hex()
                else:
                    result[key] = value
        return result
