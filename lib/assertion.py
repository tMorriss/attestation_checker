from exceptions import FormatException
from lib.assertionResponse import AssertionResponse

RESPONSE = 'response'


class Assertion:
    def __init__(self, json):
        self.json = json
        if RESPONSE not in json:
            raise FormatException(f'{RESPONSE}')

        self.response = AssertionResponse(json[RESPONSE])

    def dump(self):
        result = {}
        for key in self.json.keys():
            if key == RESPONSE:
                result[key] = self.response.dump()
            else:
                result[key] = self.json[key]
        return result
