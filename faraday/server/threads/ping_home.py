"""
Faraday Penetration Test IDE
Copyright (C) 2020  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
# Standard library imports
import logging
import threading

# Related third party imports
import requests

# Local application imports
import faraday

logger = logging.getLogger(__name__)

RUN_INTERVAL = 43200
HOME_URL = "https://portal.faradaysec.com/api/v1/license_check"


class PingHomeThread(threading.Thread):
    def __init__(self):
        super().__init__(name="PingHomeThread")
        self.__event = threading.Event()

    def run(self):
        logger.info("Ping Home Thread [Start]")
        while not self.__event.is_set():
            try:
                res = requests.get(HOME_URL, params={'version': faraday.__version__, 'key': 'white'},
                                   timeout=1, verify=True)
                if res.status_code != 200:
                    logger.error("Invalid response from portal")
                else:
                    logger.debug("Ping Home")
            except Exception as ex:
                logger.exception(ex)
                logger.warning("Can't connect to portal...")
            self.__event.wait(RUN_INTERVAL)
        else:
            logger.info("Ping Home Thread [Stop]")

    def stop(self):
        logger.info("Ping Home Thread [Stopping...]")
        self.__event.set()
