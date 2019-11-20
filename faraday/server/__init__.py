# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import logging
import threading
from time import sleep

import requests

import faraday

logger = logging.getLogger(__name__)


class TimerClass(threading.Thread):
    def __init__(self):
        super().__init__(name="TimerClassThread")
        self.__event = threading.Event()

    def run(self):
        while not self.__event.is_set():
            try:
                sleep(5)
                res = requests.get("https://portal.faradaysec.com/api/v1/license_check",
                                   params={'version': faraday.__version__, 'key': 'white'},
                                   timeout=1,
                                   verify=True)
                logger.info('License status {0}'.format(res.json().get('license_status', 'FAILED!')))
            except Exception as ex:
                logger.exception(ex)
                logger.warn(
                    "NEWS: Can't connect to faradaysec.com...")

            self.__event.wait(43200)

    def stop(self):
        self.__event.set()
