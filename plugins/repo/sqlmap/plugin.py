#!/usr/bin/env python

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

from __future__ import with_statement

import argparse
import hashlib
import os
import pickle
import re
import shlex
import socket
import sqlite3
import sys
from BaseHTTPServer import BaseHTTPRequestHandler
from StringIO import StringIO
from urlparse import urlparse

from plugins.plugin import PluginTerminalOutput

try:
    import xml.etree.cElementTree as ET
    import xml.etree.ElementTree as ET_ORIG
    ETREE_VERSION = ET_ORIG.VERSION
except ImportError:
    import xml.etree.ElementTree as ET
    ETREE_VERSION = ET.VERSION

ETREE_VERSION = [int(i) for i in ETREE_VERSION.split(".")]

current_path = os.path.abspath(os.getcwd())

__author__ = "Francisco Amato"
__copyright__ = "Copyright (c) 2013, Infobyte LLC"
__credits__ = ["Francisco Amato"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Francisco Amato"
__email__ = "famato@infobytesec.com"
__status__ = "Development"


class Database(object):

    def __init__(self, database):
        self.database = database

    def connect(self, who="server"):

        self.connection = sqlite3.connect(
            self.database, timeout=3, isolation_level=None)

        self.cursor = self.connection.cursor()

    def disconnect(self):
        self.cursor.close()
        self.connection.close()

    def commit(self):
        self.cursor.commit()

    def execute(self, statement, arguments=None):
        if arguments:
            self.cursor.execute(statement, arguments)
        else:
            self.cursor.execute(statement)

        if statement.lstrip().upper().startswith("SELECT"):
            return self.cursor.fetchall()


class SqlmapPlugin(PluginTerminalOutput):
    # Plugin for Sqlmap Tool
    def __init__(self):

        PluginTerminalOutput.__init__(self)
        self.id = "Sqlmap"
        self.name = "Sqlmap"
        self.plugin_version = "0.0.3"
        self.version = "1.0.8.15#dev"
        self.framework_version = "1.0.0"
        self._current_output = None
        self.url = ""
        self.protocol = ""
        self.hostname = ""
        self.port = "80"
        self.params = ""
        self.fullpath = ""
        self.path = ""

        self.addSetting("Sqlmap path", str, "/root/tools/sqlmap")

        self.db_port = {
            "MySQL": 3306, "PostgreSQL": "", "Microsoft SQL Server": 1433,
            "Oracle": 1521, "Firebird": 3050,
            "SAP MaxDB": 7210, "Sybase": 5000,
            "IBM DB2": 50000, "HSQLDB": 9001}

        self.ptype = {
            1: "Unescaped numeric",
            2: "Single quoted string",
            3: "LIKE single quoted string",
            4: "Double quoted string",
            5: "LIKE double quoted string",
        }

        self._command_regex = re.compile(
            r'^(python2 ./sqlmap.py|python2.7 ./sqlmap.py|sudo sqlmap|sqlmap|sudo python sqlmap|python sqlmap|\.\/sqlmap).*?')

        global current_path
        self._output_path = ''

    class HTTPRequest(BaseHTTPRequestHandler):

        def __init__(self, request_text):
            self.rfile = StringIO(request_text)
            self.raw_requestline = self.rfile.readline()
            self.error_code = self.error_message = None
            self.parse_request()

        def send_error(self, code, message):
            self.error_code = code
            self.error_message = message

    def hashKey(self, key):
        if isinstance(key, unicode):
            key = key.encode(UNICODE_ENCODING)
        else:
            key = repr(key).strip("'")

        retVal = int(hashlib.md5(key).hexdigest(), 16) & 0x7fffffffffffffff
        return retVal

    def hashDBRetrieve(self, key, unserialize=False, db=False):
        """
        Helper function for restoring session data from HashDB
        """

        key = "%s%s%s" % (self.url or "%s%s" % (
            self.hostname, self.port), key, self.HASHDB_MILESTONE_VALUE)
        retVal = ''

        hash_ = self.hashKey(key)

        if not retVal:
            while True:
                try:
                    for row in db.execute("SELECT value FROM storage WHERE id=?", (hash_,)):
                        retVal = row[0]
                except sqlite3.OperationalError, ex:
                    if not 'locked' in ex.message:
                        raise
                else:
                    break

        return retVal if not unserialize else self.base64unpickle(retVal)

    def base64decode(self, value):
        """
        Decodes string value from Base64 to plain format

        >>> base64decode('Zm9vYmFy')
        'foobar'
        """

        return value.decode("base64")

    def base64encode(self, value):
        """
        Encodes string value from plain to Base64 format

        >>> base64encode('foobar')
        'Zm9vYmFy'
        """

        return value.encode("base64")[:-1].replace("\n", "")

    def base64unpickle(self, value):
        """
        Decodes value from Base64 to plain format and deserializes (with pickle) its content

        >>> base64unpickle('gAJVBmZvb2JhcnEALg==')
        'foobar'
        """
        if value:
            return pickle.loads(self.base64decode(value))

    def xmlvalue(self, db, name, value="query"):

        filepath = "%s" % os.path.join(
            current_path, "plugins/repo/sqlmap/queries.xml")
        with open(filepath, "r") as f:
            try:
                tree = ET.fromstring(f.read())
            except SyntaxError, err:
                print "SyntaxError: %s. %s" % (err, filepath)
                return None

        for node in tree.findall("dbms[@value='" + db + "']/" + name + ''):
            return node.attrib[value]

    def getuser(self, data):

        users = re.search(
            r'database management system users \[[\d]+\]:\n((\[\*\] (.*)\n)*)',
            data)

        if users:
            return map((lambda x: x.replace("[*] ", "")), users.group(1).split("\n"))

    def getdbs(self, data):

        dbs = re.search(
            r'available databases \[[\d]+\]:\n(((\[\*\] (.*)\n)*))',
            data)

        if dbs:
            return map((lambda x: x.replace("[*] ", "")), dbs.group(1).split("\n"))

    def getpassword(self, data):

        users = {}

        password = re.findall(
            r"\n\[\*\] (.*) \[\d\]:\n\s*password hash: (.*)",
            data)

        if password:
            for credential in password:

                user = credential[0]
                mpass = credential[1]
                users[user] = mpass

        return users

    def getAddress(self, hostname):
        """
        Returns remote IP address from hostname.
        """
        try:
            return socket.gethostbyname(hostname)
        except socket.error:
            return self.hostname

    def parseOutputString(self, output, debug=False):
        """
        This method will discard the output the shell sends, it will read it from
        the xml where it expects it to be present.

        NOTE: if 'debug' is true then it is being run from a test case and the
        output being sent is valid.
        """

        sys.path.append(self.getSetting("Sqlmap path"))

        try:
            from lib.core.settings import HASHDB_MILESTONE_VALUE
            from lib.core.enums import HASHDB_KEYS
            from lib.core.settings import UNICODE_ENCODING
        except:
            print 'ERROR: Remember set your Sqlmap Path Setting!... Abort plugin.'
            sys.exit(-1)

        self.HASHDB_MILESTONE_VALUE = HASHDB_MILESTONE_VALUE
        self.HASHDB_KEYS = HASHDB_KEYS
        self.UNICODE_ENCODING = UNICODE_ENCODING

        password = self.getpassword(output)

        webserver = re.search("web application technology: (.*?)\n", output)
        if webserver:
            webserver = webserver.group(1)

        users = self.getuser(output)
        dbs = self.getdbs(output)

        db = Database(self._output_path)
        db.connect()

        absFilePaths = self.hashDBRetrieve(
            self.HASHDB_KEYS.KB_ABS_FILE_PATHS, True, db)

        tables = self.hashDBRetrieve(
            self.HASHDB_KEYS.KB_BRUTE_TABLES, True, db)

        columns = self.hashDBRetrieve(
            self.HASHDB_KEYS.KB_BRUTE_COLUMNS, True, db)

        xpCmdshellAvailable = self.hashDBRetrieve(
            self.HASHDB_KEYS.KB_XP_CMDSHELL_AVAILABLE, True, db)

        dbms_version = self.hashDBRetrieve(self.HASHDB_KEYS.DBMS, False, db)

        os = self.hashDBRetrieve(self.HASHDB_KEYS.OS, False, db)

        self.ip = self.getAddress(self.hostname)

        dbms = str(dbms_version.split(" ")[0])

        h_id = self.createAndAddHost(self.ip)

        i_id = self.createAndAddInterface(
            h_id,
            name=self.ip,
            ipv4_address=self.ip,
            hostname_resolution=self.hostname)

        s_id = self.createAndAddServiceToInterface(
            h_id,
            i_id,
            self.protocol,
            'tcp',
            [self.port],
            status="open",
            version=webserver)

        n_id = self.createAndAddNoteToService(
            h_id,
            s_id,
            "website",
            '')

        n2_id = self.createAndAddNoteToNote(
            h_id,
            s_id,
            n_id,
            self.hostname,
            '')

        db_port = self.db_port[dbms]

        s_id2 = self.createAndAddServiceToInterface(
            h_id,
            i_id,
            name=dbms,
            protocol="tcp",
            status="down",
            version=str(dbms_version),
            ports=[str(db_port)],
            description="DB detect by SQLi")

        # sqlmap.py --users
        if users:
            for v in users:
                if v:
                    self.createAndAddCredToService(h_id, s_id2, v, '')

        # sqlmap.py --passwords
        if password:
            for k, v in password.iteritems():
                self.createAndAddCredToService(h_id, s_id2, k, v)

        if absFilePaths:
            n_id2 = self.createAndAddNoteToService(
                h_id,
                s_id2,
                "sqlmap.absFilePaths",
                str(absFilePaths))

        # sqlmap.py --common-tables
        if tables:
            for item in tables:
                n_id2 = self.createAndAddNoteToService(
                    h_id,
                    s_id2,
                    "sqlmap.brutetables",
                    item[1])

        # sqlmap.py --common-columns
        if columns:

            text = (
                'Db: ' + columns[0][0] +
                '\nTable: ' + columns[0][1] +
                '\nColumns:')

            for element in columns:
                text += str(element[2]) + '\n'

            n_id2 = self.createAndAddNoteToService(
                h_id,
                s_id2,
                "sqlmap.brutecolumns",
                text)

        # sqlmap.py  --os-shell
        if xpCmdshellAvailable:
            n_id2 = self.createAndAddNoteToService(
                h_id,
                s_id2,
                "sqlmap.xpCmdshellAvailable",
                str(xpCmdshellAvailable))

        for inj in self.hashDBRetrieve(self.HASHDB_KEYS.KB_INJECTIONS, True, db) or []:

            dbversion = self.hashDBRetrieve(
                "None" + self.xmlvalue(dbms, "banner"), False, db)

            user = self.hashDBRetrieve(
                "None" + self.xmlvalue(dbms, "current_user"), False, db)

            dbname = self.hashDBRetrieve(
                "None" + self.xmlvalue(dbms, "current_db"), False, db)

            hostname = self.hashDBRetrieve(
                "None" + self.xmlvalue(dbms, "hostname"), False, db)

            if user:
                n_id2 = self.createAndAddNoteToService(
                    h_id,
                    s_id2,
                    "db.user",
                    user)

            if dbname:
                n_id2 = self.createAndAddNoteToService(
                    h_id,
                    s_id2,
                    "db.name",
                    dbname)

            if hostname:
                n_id2 = self.createAndAddNoteToService(
                    h_id,
                    s_id2,
                    "db.hostname",
                    hostname)

            if dbversion:
                n_id2 = self.createAndAddNoteToService(
                    h_id,
                    s_id2,
                    "db.version",
                    dbversion)

            if dbs:
                n_id2 = self.createAndAddNoteToService(
                    h_id,
                    s_id2,
                    "db.databases",
                    str(dbs))

            for k, v in inj.data.items():
                v_id = self.createAndAddVulnWebToService(
                    h_id,
                    s_id,
                    website=self.hostname,
                    name=inj.data[k]['title'],
                    desc="Payload:" + str(inj.data[k]['payload']) + "\nVector:" + str(inj.data[k]['vector']) +
                    "\nParam type:" + str(self.ptype[inj.ptype]),
                    ref=[],
                    pname=inj.parameter,
                    severity="high",
                    method=inj.place,
                    params=self.params,
                    path=self.fullpath)

    def processCommandString(self, username, current_path, command_string):

        parser = argparse.ArgumentParser(conflict_handler='resolve')

        parser.add_argument('-h')
        parser.add_argument('-u')
        parser.add_argument('-s')
        parser.add_argument('-r')

        try:
            args, unknown = parser.parse_known_args(
                shlex.split(re.sub(r'\-h|\-\-help', r'', command_string)))
        except SystemExit:
            pass

        if args.r:
            with open(args.r, 'r') as f:
                request = self.HTTPRequest(f.read())
                args.u = "http://" + request.headers['host'] + request.path
                f.close()

        if args.u:

            urlComponents = urlparse(args.u)

            self.protocol = urlComponents.scheme
            self.hostname = urlComponents.netloc

            if urlComponents.port:
                self.port = urlComponents.port
            else:
                self.port = '80'

            if urlComponents.query:
                self.path = urlComponents.path
                self.params = urlComponents.query

            self.url = self.protocol + "://" + self.hostname + ":" + self.port + self.path
            self.fullpath = self.url + "?" + self.params

            self._output_path = "%s%s" % (
                os.path.join(self.data_path, "sqlmap_output-"),
                re.sub(r'[\n\/]', r'',
                args.u.encode("base64")[:-1]))

        if not args.s:
            return "%s -s %s" % (command_string, self._output_path)

    def setHost(self):
        pass


def createPlugin():
    return SqlmapPlugin()
