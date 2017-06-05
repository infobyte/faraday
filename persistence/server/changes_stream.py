#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import time
import json
import threading
from Queue import Queue, Empty

import requests
import websocket

from persistence.server.server_io_exceptions import (
    ChangesStreamStoppedAbruptly
)


class ChangesStream(object):

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return False

    def __next__(self):
        return self

    def __iter__(self):
        raise NotImplementedError('Abstract class')

    def _get_object_type_and_name_from_change(self, change):
        try:
            id = change['id']
            response = requests.get("{0}/{1}".format(self._base_url, id), **self._params)
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


class WebsocketsChangesStream(ChangesStream):
    def __init__(self, workspace_name, server_url, **params):
        self._base_url = server_url
        self.changes_queue = Queue()
        self.workspace_name = workspace_name
        self._response = None
        websocket.enableTrace(True)
        self.ws = websocket.WebSocketApp(
                "ws://{0}:9000".format(self._base_url),
                on_message=self.on_message,
                on_error=self.on_error,
                on_close=self.on_close)

        self.ws.on_open = self.on_open
        thread = threading.Thread(target=self.ws.run_forever, args=())
        thread.daemon = True
        thread.start()

    def on_message(self, ws, message):
        self.changes_queue.put(message)

    def on_error(self, ws, error):
        print error

    def on_close(selg, ws):
        print "### closed ###"

    def on_open(self, ws):
        print 'open'

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return False

    def __next__(self):
        return self

    def __iter__(self):
        try:
            data = json.loads(self.changes_queue.get_nowait())
        except Empty:
            raise StopIteration
        yield data

    def _get_object_type_and_name_from_change(self, change):
        try:
            id = change['id']
            response = requests.get("{0}/{1}".format(self._base_url, id), **self._params)
            object_json = response.json()
        except Exception:
            return None, None
        return object_json.get('type'), object_json.get('name')


class CouchChangesStream(ChangesStream):

    def __init__(self, workspace_name, server_url, since=0, heartbeat='1000', feed='continuous', **params):
        self._base_url = server_url
        self._change_url = "{0}/_changes".format(server_url)
        self.since = since
        self.heartbeat = heartbeat
        self.feed = feed
        self._params = params
        self._response = None
        self._stop = False

    def __iter__(self):
        try:
            params = {'since' : self.since, 'heartbeat': self.heartbeat, 'feed': self.feed}
            self._response = requests.get(self._change_url, stream=True, params=params, **self._params)
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
                if not self._stop:  # why did we stop if no one asked me to stop?
                    raise ChangesStreamStoppedAbruptly

        except (requests.exceptions.RequestException, ChangesStreamStoppedAbruptly):
            self.stop()
            raise ChangesStreamStoppedAbruptly
        except Exception as e:
            self.stop()
