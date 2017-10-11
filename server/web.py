# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import os
import functools
import twisted.web
from twisted.web.resource import Resource

import server.config

from twisted.web import proxy
from twisted.internet import ssl, reactor, error
from twisted.protocols.tls import TLSMemoryBIOFactory
from twisted.web.static import File
from twisted.web.wsgi import WSGIResource
from server.utils import logger
from server.app import create_app

app = create_app()  # creates a Flask(__name__) app


class WebServer(object):
    UI_URL_PATH = '_ui'
    API_URL_PATH = '_api'
    WEB_UI_LOCAL_PATH = os.path.join(server.config.FARADAY_BASE, 'server/www')

    def __init__(self, enable_ssl=False):
        logger.get_logger(__name__).info('Starting server at port {0} with bind address {1}. SSL {2}'.format(
            server.config.faraday_server.port,
            server.config.faraday_server.bind_address,
            enable_ssl))
        self.__ssl_enabled = enable_ssl
        self.__config_server()
        self.__build_server_tree()

    def __config_server(self):
        self.__bind_address = server.config.faraday_server.bind_address
        self.__listen_port = int(server.config.faraday_server.port)
        if self.__ssl_enabled:
            self.__listen_port = int(server.config.ssl.port)

    def __load_ssl_certs(self):
        certs = (server.config.ssl.keyfile, server.config.ssl.certificate)
        if not all(certs):
            logger.get_logger(__name__).critical("HTTPS request but SSL certificates are not configured")
            exit(1) # Abort web-server startup
        return ssl.DefaultOpenSSLContextFactory(*certs)

    def __build_server_tree(self):
        self.__root_resource = Resource()
        self.__root_resource.putChild(
            WebServer.UI_URL_PATH, self.__build_web_resource())
        self.__root_resource.putChild(
            WebServer.API_URL_PATH, self.__build_api_resource())

    def __build_web_resource(self):
        return File(WebServer.WEB_UI_LOCAL_PATH)

    def __build_api_resource(self):
        return WSGIResource(reactor, reactor.getThreadPool(), app)

    def run(self):
        site = twisted.web.server.Site(self.__root_resource)
        if self.__ssl_enabled:
            ssl_context = self.__load_ssl_certs()
            self.__listen_func = functools.partial(
                reactor.listenSSL,
                contextFactory = ssl_context)
        else:
            self.__couchdb_port = int(server.config.couchdb.port)
            self.__listen_func = reactor.listenTCP

        self.__listen_func(
            self.__listen_port, site,
            interface=self.__bind_address)
        reactor.run()

