import requests, json

class CouchChangesStream(object):
    def __init__(self, workspace_name, server_url, **params):
        self._base_url = server_url
        self._change_url = "{0}/_changes".format(server_url)
        self._params = params
        self._response = None
        self._stop = False

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return False

    def __next__(self):
        return self

    def __iter__(self):
        try:
            self._response = requests.get(self._change_url, self._params, stream=True)
            if self._response:
                for raw_line in self._response.iter_lines():
                    line = self._sanitize(raw_line)
                    if not line:
                        if self._stop: break
                        else: continue
                    change = self._parse_change(line)
                    if not change:
                        continue
                    object_type, object_name = self._get_object_type_and_name_from_change(change)
                    yield change, object_type, object_name
        except requests.exceptions.RequestException:
            self.stop()
            raise
        except Exception as e:
            self.stop()

    def _get_object_type_and_name_from_change(self, change):
        try:
            id = change['id']
            response = requests.get("{0}/{1}".format(self._base_url, id))
            object_json = response.json()
        except Exception:
            return None, None
        return object_json.get('type'), object_json.get('name')

    def _sanitize(self, raw_line):
        if not isinstance(raw_line, basestring):
            return None
        line = raw_line.strip()
        if not line or line in ('{"results":', '],'):
            return None
        if line.startswith('"last_seq"'):
            line = '{' + line
        if line.endswith(","):
            line = line[:-1]
        return line

    def _parse_change(self, line):
        try:
            obj = json.loads(line)
            return obj
        except ValueError:
            return None

    def stop(self):
        if self._response is not None:
            self._response.close()
            self._response = None
        self._stop = True
