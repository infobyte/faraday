# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import json
import logging
import threading
from time import sleep

import requests

import faraday

logger = logging.getLogger(__name__)


class TimerClass(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.__event = threading.Event()

    def sendNewstoLogGTK(self, json_response):

        information = json.loads(json_response)

        for news in information.get("news", []):
            faraday.client.model.guiapi.notification_center.sendCustomLog(
                "NEWS -" + news["url"] + "|" + news["description"])

    def run(self):
        while not self.__event.is_set():
            try:
                sleep(5)
                res = requests.get(
                    "https://portal.faradaysec.com/api/v1/license_check",
                    params={'version': faraday.__version__,
                            'key': 'white'},
                    timeout=1,
                    verify=True)

                self.sendNewstoLogGTK(res.text)
                logger.info('License status {0}'.format(res.json().get('license_status', 'FAILED!')))
            except Exception as ex:
                logger.exception(ex)
                logger.warn(
                    "NEWS: Can't connect to faradaysec.com...")

            self.__event.wait(43200)

    def stop(self):
        self.__event.set()