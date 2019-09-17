import json


class BytesJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (bytes, bytearray)):
            return obj.decode("ASCII")
        return json.JSONEncoder.default(self, obj)

# I'm Py3
