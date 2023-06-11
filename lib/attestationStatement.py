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
                result[key] = 'x5c certificates.....'
            else:
                value = self.json[key]
                if type(value) is bytes:
                    result[key] = value.hex()
                else:
                    result[key] = value
        return result


class Packed(AttestationStatement):
    def __init__(self, raw):
        self.raw = raw

    def dump(self):
        return ''


class AndroidSafetyNet(AttestationStatement):
    def __init__(self, raw):
        self.raw = raw

    def dump(self):
        return ''


class Apple(AttestationStatement):
    def __init__(self, raw):
        self.raw = raw

    def dump(self):
        return ''
