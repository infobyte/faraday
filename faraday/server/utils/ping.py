import logging

from gevent.event import Event
import requests

from faraday import __version__
from faraday.server.extensions import socketio

logger = logging.getLogger(__name__)

RUN_INTERVAL = 43200
HOME_URL = "https://portal.faradaysec.com/api/v1/license_check"

stop_ping_event = Event()


def ping_home_background_task():
    while not stop_ping_event.is_set():
        try:
            res = requests.get(HOME_URL, params={'version': __version__, 'key': 'white'}, timeout=1, verify=True)
            if res.status_code != 200:
                logger.error("Invalid response from portal")
            else:
                logger.debug("Ping Home")
        except Exception as ex:
            logger.exception(ex)
            logger.warning("Can't connect to portal...")
        socketio.sleep(RUN_INTERVAL)
    else:
        logger.info("Ping background task stopped")
