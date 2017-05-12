#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import urlparse

def get_vulnweb_url_fields(url):
    """Given a URL, return kwargs to pass to createAndAddVulnWebToService."""
    parse = urlparse.urlsplit(url)
    return {
        "website": "{}://{}".format(parse.scheme, parse.netloc),
        "path": parse.path,
        "query": parse.query
        }
