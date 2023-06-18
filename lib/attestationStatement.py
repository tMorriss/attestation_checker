import base64
from abc import ABCMeta, abstractmethod

X5C = 'x5c'


class AttestationStatement(metaclass=ABCMeta):
    @abstractmethod
    def __init__(self, raw):
        raise NotImplementedError()

    @abstractmethod
    def dump(self):
        raise NotImplementedError()


class NoneFmt(AttestationStatement):
    def __init__(self, raw):
        self.raw = raw

    def dump(self):
        return self.raw


class Tpm(AttestationStatement):
    def __init__(self, json):
        self.json = json

    def dump(self):
        result = {}
        for key in self.json.keys():
            if key == X5C:
                result[key] = []
                for cert in self.json[key]:
                    result[key].append(base64.b64encode(cert).decode())
                    print(type(cert))
            else:
                value = self.json[key]
                if type(value) is bytes:
                    result[key] = value.hex()
                else:
                    result[key] = value
        return result


class Packed(AttestationStatement):
    def __init__(self, json):
        self.json = json

    def dump(self):
        result = {}
        for key in self.json.keys():
            if key == X5C:
                result[key] = []
                for cert in self.json[key]:
                    result[key].append(base64.b64encode(cert).decode())
                    print(type(cert))
            else:
                value = self.json[key]
                if type(value) is bytes:
                    result[key] = value.hex()
                else:
                    result[key] = value
        return result


class AndroidSafetyNet(AttestationStatement):
    def __init__(self, raw):
        self.raw = raw

    def dump(self):
        return 'TBD...'


class Apple(AttestationStatement):
    def __init__(self, raw):
        self.raw = raw

    def dump(self):
        return 'TBD...'
