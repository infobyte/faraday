#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
class ServerRequestException(Exception):
    def __init__(self):
        pass

class MoreThanOneObjectFoundByID(ServerRequestException):
    def __init__(self, faulty_list):
        self.faulty_list = faulty_list

    def __str__(self):
        return ("More than one object has been found."
                "These are all the objects found with the same ID: {0}"
                .format(self.faulty_list))


class CantCommunicateWithServerError(ServerRequestException):
    def __init__(self, function, server_url, payload, response):
        self.function = function
        self.server_url = server_url
        self.payload = payload
        self.response = response

    def __str__(self):
        return ("Couldn't get a valid response from the server when requesting "
                "to URL {0} and function {1}. Response was {2}".format(self.server_url,
                                                      self.function, self.response.text))

class ConflictInDatabase(ServerRequestException):
    def __init__(self, answer):
        self.answer = answer

    def __str__(self):
        return ("There was a conflict trying to save your document. "
                "Most probably the document already existed and you "
                "did not provided a _rev argument to your payload. "
                "The answer from the server was {0}".format(self.answer))

class ResourceDoesNotExist(ServerRequestException):
    def __init__(self, url):
        self.url = url

    def __str__(self):
        return ("Can't find anything on URL {0}".format(self.url))

class Unauthorized(ServerRequestException):
    def __init__(self, answer):
        self.answer = answer

    def __str__(self):
        return ("You're not authorized to make this request. "
                "The answer from the server was {0}. Plase check that your domain is the correct one.".format(self.answer))

class CouchDBException(Exception):
    def __init__(self):
        pass

class ChangesStreamStoppedAbruptly(CouchDBException):
    def __str__(self):
        return ("The changes stream from CouchDB ended abruptly for some "
                "unkown reason.")


class WrongObjectSignature(Exception):
    def __init__(self, param):
        self.param = param

    def __str__(self):
        return ("object_signature must be either 'host', 'vuln', 'vuln_web',"
                "'interface' 'service', 'credential' or 'note' and it was {0}"
                .format(self.param))

class CantAccessConfigurationWithoutTheClient(Exception):
    def __init__(self):
        pass

    def __str__(self):
        return ("You're tring to access to the Faraday Configuration without "
                "having the client up. This is not possible at the moment.")
