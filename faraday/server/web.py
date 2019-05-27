# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import os
import sys
import functools
from signal import SIGABRT, SIGILL, SIGINT, SIGSEGV, SIGTERM, SIG_DFL, signal

import twisted.web
from twisted.web.resource import Resource, ForbiddenResource

import faraday.server.config

from twisted.internet import ssl, reactor, error
from twisted.web.static import File
from twisted.web.util import Redirect
from twisted.web.wsgi import WSGIResource
from autobahn.twisted.websocket import (
    listenWS
)
import faraday.server.config
from faraday.server.utils import logger

from faraday.server.app import create_app
from faraday.server.websocket_factories import (
    WorkspaceServerFactory,
    BroadcastServerProtocol
)
from faraday.server.api.modules.upload_reports import RawReportProcessor

app = create_app()  # creates a Flask(__name__) app
logger = faraday.server.utils.logger.get_logger(__name__)


class CleanHttpHeadersResource(Resource, object):
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


class FaradayWSGIResource(WSGIResource, object):
    def render(self, request):
        request.responseHeaders.removeHeader('Server')
        return super(FaradayWSGIResource, self).render(request)


class FaradayRedirectResource(Redirect, object):
    def render(self, request):
        request.responseHeaders.removeHeader('Server')
        return super(FaradayRedirectResource, self).render(request)


class WebServer(object):
    UI_URL_PATH = '_ui'
    API_URL_PATH = '_api'
    WEB_UI_LOCAL_PATH = os.path.join(faraday.server.config.FARADAY_BASE, 'server/www')

    def __init__(self, enable_ssl=False):
        logger.info('Starting web server at {}://{}:{}/'.format(
            'https' if enable_ssl else 'http',
            faraday.server.config.faraday_server.bind_address,
            faraday.server.config.faraday_server.port))
        self.__ssl_enabled = enable_ssl
        self.__config_server()
        self.__build_server_tree()

    def __config_server(self):
        self.__bind_address = faraday.server.config.faraday_server.bind_address
        self.__listen_port = int(faraday.server.config.faraday_server.port)
        if self.__ssl_enabled:
            self.__listen_port = int(faraday.server.config.ssl.port)

    def __load_ssl_certs(self):
        certs = (faraday.server.config.ssl.keyfile, faraday.server.config.ssl.certificate)
        if not all(certs):
            logger.critical("HTTPS request but SSL certificates are not configured")
            exit(1) # Abort web-server startup
        return ssl.DefaultOpenSSLContextFactory(*certs)

    def __build_server_tree(self):
        self.__root_resource = self.__build_web_resource()
        self.__root_resource.putChild(WebServer.UI_URL_PATH,
                                      self.__build_web_redirect())
        self.__root_resource.putChild(
            WebServer.API_URL_PATH, self.__build_api_resource())

    def __build_web_redirect(self):
        return FaradayRedirectResource('/')

    def __build_web_resource(self):
        return FileWithoutDirectoryListing(WebServer.WEB_UI_LOCAL_PATH)

    def __build_api_resource(self):
        return FaradayWSGIResource(reactor, reactor.getThreadPool(), app)

    def __build_websockets_resource(self):
        websocket_port = int(faraday.server.config.faraday_server.websocket_port)
        url = '{0}:{1}'.format(self.__bind_address, websocket_port)
        if self.__ssl_enabled:
            url = 'wss://' + url
        else:
            url = 'ws://' + url
        # logger.info(u"Websocket listening at {url}".format(url=url))
        logger.info('Starting websocket server at port {0} with bind address {1}. '
                    'SSL {2}'.format(
            websocket_port,
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
        print self.WEB_UI_LOCAL_PATH
        def signal_handler(*args):
            logger.info('Received SIGTERM, shutting down.')
            logger.info("Stopping threads, please wait...")
            # teardown()
            self.raw_report_processor.stop()

        site = twisted.web.server.Site(self.__root_resource)
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
            self.raw_report_processor = RawReportProcessor()
            self.raw_report_processor.start()
            # web and static content
            self.__listen_func(
                self.__listen_port, site,
                interface=self.__bind_address)
            # websockets
            try:
                listenWS(self.__build_websockets_resource(), interface=self.__bind_address)
            except :
                logger.warn('Could not start websockets, address already open. This is ok is you wan to run multiple instances.')
            logger.info('Faraday Server is ready')
            reactor.addSystemEventTrigger('before', 'shutdown', signal_handler)
            reactor.run()

        except error.CannotListenError as e:
            logger.error(str(e))
            sys.exit(1)
        except Exception as e:
            logger.error('Something went wrong when trying to setup the Web UI')
            logger.exception(e)
            sys.exit(1)
