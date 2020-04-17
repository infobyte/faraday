# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import os
import sys
import functools
import logging
from signal import SIGABRT, SIGILL, SIGINT, SIGSEGV, SIGTERM, SIG_DFL, signal

import twisted.web
from twisted.web.resource import Resource, ForbiddenResource

from twisted.internet import ssl, reactor, error
from twisted.web.static import File
from twisted.web.util import Redirect
from twisted.web.http import proxiedLogFormatter
from twisted.web.wsgi import WSGIResource
from autobahn.twisted.websocket import (
    listenWS
)

from OpenSSL.SSL import Error as SSLError

import faraday.server.config

from faraday.server.config import CONST_FARADAY_HOME_PATH
from faraday.server.utils import logger
from faraday.server.threads.reports_processor import ReportsManager, REPORTS_QUEUE
from faraday.server.threads.ping_home import PingHomeThread
from faraday.server.app import create_app
from faraday.server.websocket_factories import (
    WorkspaceServerFactory,
    BroadcastServerProtocol
)


app = create_app()  # creates a Flask(__name__) app
logger = logging.getLogger(__name__)


class CleanHttpHeadersResource(Resource):
    def render(self, request):
        request.responseHeaders.removeHeader('Server')
        return super(CleanHttpHeadersResource, self).render(request)


class FileWithoutDirectoryListing(File, CleanHttpHeadersResource):
    def directoryListing(self):
        return ForbiddenResource()

    def render(self, request):
        ret = super(FileWithoutDirectoryListing, self).render(request)
        if self.type == 'text/html':
            request.responseHeaders.addRawHeader('Content-Security-Policy',
                                                 'frame-ancestors \'self\'')
            request.responseHeaders.addRawHeader('X-Frame-Options', 'SAMEORIGIN')
        return ret


class FaradayWSGIResource(WSGIResource):
    def render(self, request):
        request.responseHeaders.removeHeader('Server')
        return super(FaradayWSGIResource, self).render(request)


class FaradayRedirectResource(Redirect):
    def render(self, request):
        request.responseHeaders.removeHeader('Server')
        return super(FaradayRedirectResource, self).render(request)


class WebServer:
    UI_URL_PATH = b'_ui'
    API_URL_PATH = b'_api'
    WEB_UI_LOCAL_PATH = os.path.join(faraday.server.config.FARADAY_BASE, 'server/www')

    def __init__(self):
        self.__ssl_enabled = faraday.server.config.ssl.enabled
        logger.info('Starting web server at %s://%s:%s/',
            'https' if self.__ssl_enabled else 'http',
            faraday.server.config.faraday_server.bind_address,
            faraday.server.config.ssl.port if self.__ssl_enabled else faraday.server.config.faraday_server.port)
        self.__websocket_ssl_enabled = faraday.server.config.websocket_ssl.enabled
        self.__websocket_port = faraday.server.config.faraday_server.websocket_port or 9000
        self.__config_server()
        self.__build_server_tree()

    def __config_server(self):
        self.__bind_address = faraday.server.config.faraday_server.bind_address
        if self.__ssl_enabled:
            self.__listen_port = int(faraday.server.config.ssl.port)
        else:
            self.__listen_port = int(faraday.server.config.faraday_server.port)

    def __load_ssl_certs(self):
        certs = (faraday.server.config.ssl.keyfile, faraday.server.config.ssl.certificate)
        if not all(certs):
            logger.critical("HTTPS request but SSL certificates are not configured")
            sys.exit(1) # Abort web-server startup
        return ssl.DefaultOpenSSLContextFactory(*certs)

    def __build_server_tree(self):
        self.__root_resource = self.__build_web_resource()
        self.__root_resource.putChild(WebServer.UI_URL_PATH,
                                      self.__build_web_redirect())
        self.__root_resource.putChild(
            WebServer.API_URL_PATH, self.__build_api_resource())

    def __build_web_redirect(self):
        return FaradayRedirectResource(b'/')

    def __build_web_resource(self):
        return FileWithoutDirectoryListing(WebServer.WEB_UI_LOCAL_PATH)

    def __build_api_resource(self):
        return FaradayWSGIResource(reactor, reactor.getThreadPool(), app)

    def __build_websockets_resource(self):
        websocket_port = int(faraday.server.config.faraday_server.websocket_port)
        url = '{0}:{1}/websockets'.format(self.__bind_address, websocket_port)
        if self.__websocket_ssl_enabled:
            url = 'wss://' + url
        else:
            url = 'ws://' + url
        # logger.info(u"Websocket listening at {url}".format(url=url))
        logger.info('Starting websocket server at port {0} with bind address {1}. '
                    'SSL {2}'.format(
            self.__websocket_port,
            self.__bind_address,
            self.__ssl_enabled
        ))

        factory = WorkspaceServerFactory(url=url)
        factory.protocol = BroadcastServerProtocol
        return factory

    def install_signal(self):
        for sig in (SIGABRT, SIGILL, SIGINT, SIGSEGV, SIGTERM):
            signal(sig, SIG_DFL)

    def run(self):
        def signal_handler(*args):
            logger.info('Received SIGTERM, shutting down.')
            logger.info("Stopping threads, please wait...")
            # teardown()
            if self.raw_report_processor.isAlive():
                self.raw_report_processor.stop()
            self.ping_home_thread.stop()

        log_path = os.path.join(CONST_FARADAY_HOME_PATH, 'logs', 'access-logging.log')
        site = twisted.web.server.Site(self.__root_resource,
                                       logPath=log_path,
                                       logFormatter=proxiedLogFormatter)
        site.displayTracebacks = False
        if self.__ssl_enabled:
            ssl_context = self.__load_ssl_certs()
            self.__listen_func = functools.partial(
                reactor.listenSSL,
                contextFactory=ssl_context)
        else:
            self.__listen_func = reactor.listenTCP

        try:
            self.install_signal()
            # start threads and processes
            self.raw_report_processor = ReportsManager(REPORTS_QUEUE, name="ReportsManager-Thread", daemon=True)
            self.raw_report_processor.start()
            self.ping_home_thread = PingHomeThread()
            self.ping_home_thread.start()
            # web and static content
            self.__listen_func(
                self.__listen_port, site,
                interface=self.__bind_address)
            # websockets
            if faraday.server.config.websocket_ssl.enabled:

                try:
                    contextFactory = ssl.DefaultOpenSSLContextFactory(
                            faraday.server.config.websocket_ssl.keyfile.strip('\''),
                            faraday.server.config.websocket_ssl.certificate.strip('\'')
                    )

                    listenWS(self.__build_websockets_resource(), interface=self.__bind_address, contextFactory=contextFactory)

                except SSLError as e:
                    logger.error('Could not start websockets due to a SSL Config error. Some web functionality will not be available')
                except error.CannotListenError:
                    logger.warn('Could not start websockets, address already open. This is ok is you wan to run multiple instances.')
                except Exception as ex:
                    logger.warn('Could not start websocket, error: {}'.format(ex))
            else:
                try:
                    listenWS(self.__build_websockets_resource(), interface=self.__bind_address)
                except error.CannotListenError:
                    logger.warn('Could not start websockets, address already open. This is ok is you wan to run multiple instances.')
                except Exception as ex:
                    logger.warn('Could not start websocket, error: {}'.format(ex))
            logger.info('Faraday Server is ready')
            reactor.addSystemEventTrigger('before', 'shutdown', signal_handler)
            reactor.run()

        except error.CannotListenError as e:
            logger.error(e)
            sys.exit(1)


        except Exception as e:
            logger.exception('Something went wrong when trying to setup the Web UI')
            sys.exit(1)
# I'm Py3
