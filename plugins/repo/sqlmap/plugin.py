#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from __future__ import with_statement
import sys
import os

from plugins.plugin import PluginTerminalOutput
from model import api
import re
import os
import pprint
import json
import pickle
import sqlite3
import hashlib
import socket
import argparse
import shlex
from BaseHTTPServer import BaseHTTPRequestHandler
from StringIO import StringIO


try:
    import xml.etree.cElementTree as ET
    import xml.etree.ElementTree as ET_ORIG
    ETREE_VERSION = ET_ORIG.VERSION
except ImportError:
    import xml.etree.ElementTree as ET
    ETREE_VERSION = ET.VERSION

ETREE_VERSION = [int(i) for i in ETREE_VERSION.split(".")]

current_path = os.path.abspath(os.getcwd())

__author__     = "Francisco Amato"
__copyright__  = "Copyright (c) 2013, Infobyte LLC"
__credits__    = ["Francisco Amato"]
__license__    = ""
__version__    = "1.0.0"
__maintainer__ = "Francisco Amato"
__email__      = "famato@infobytesec.com"
__status__     = "Development"


class Database(object):

    def __init__(self, database):
        self.database = database


    def connect(self, who="server"):
        # print "Db" + self.database
        self.connection = sqlite3.connect(self.database, timeout=3, isolation_level=None)
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
    """
    Example plugin to parse sqlmap output.
    """
    def __init__(self):
        PluginTerminalOutput.__init__(self)
        self.id              = "Sqlmap"
        self.name            = "Sqlmap"
        self.plugin_version         = "0.0.2"
        self.version   = "1.0-dev-6bcc95"
        self.framework_version  = "1.0.0"
        self._current_output = None
        self.url = ""
        self.protocol=""
        self.hostname=""
        self.port="80"
        self.params=""
        self.fullpath=""
        self.path=""

        self.addSetting("Sqlmap path", str, "/root/tools/sqlmap")

        self.db_port = { "MySQL" : 3306, "PostgreSQL":"", "Microsoft SQL Server" : 1433,
                 "Oracle" : 1521, "Firebird" : 3050,"SAP MaxDB":7210, "Sybase" : 5000,
                 "IBM DB2" : 50000, "HSQLDB" :9001}
        self.ptype = {
                    1: "Unescaped numeric",
                    2: "Single quoted string",
                    3: "LIKE single quoted string",
                    4: "Double quoted string",
                    5: "LIKE double quoted string",
                }

        self._command_regex  = re.compile(r'^(python2.7 ./sqlmap.py|sudo sqlmap|sqlmap|sudo python sqlmap|python sqlmap|\.\/sqlmap).*?')

        global current_path
        self._output_path = ""
        self._completition = {
                                "-h,":"Show basic help message and exit",
                                "-hh":"Show advanced help message and exit",
                                "--version":"Show program's version number and exit",
                                "-v":"VERBOSE            Verbosity level: 0-6 (default 1)",
                                "-d":"DIRECT           Direct connection to the database",
                                "-u":"URL, --url=URL   Target URL (e.g. \"www.target.com/vuln.php?id=1\")",
                                "-l":"LOGFILE          Parse targets from Burp or WebScarab proxy logs",
                                "-m":"BULKFILE         Scan multiple targets enlisted in a given textual file",
                                "-r":"REQUESTFILE      Load HTTP request from a file",
                                "-g":"GOOGLEDORK       Process Google dork results as target URLs",
                                "-c":"CONFIGFILE       Load options from a configuration INI file",
                                "--data":"DATA         Data string to be sent through POST",
                                "--param-del":"PDEL    Character used for splitting parameter values",
                                "--cookie":"COOKIE     HTTP Cookie header",
                                "--cookie-del":"CDEL   Character used for splitting cookie values",
                                "--load-cookies":"L..  File containing cookies in Netscape/wget format",
                                "--drop-set-cookie":"   Ignore Set-Cookie header from response",
                                "--user-agent":"AGENT  HTTP User-Agent header",
                                "--random-agent":"Use randomly selected HTTP User-Agent header",
                                "--host":"HOST         HTTP Host header",
                                "--referer":"REFERER   HTTP Referer header",
                                "--headers":"HEADERS   Extra headers (e.g. \"Accept-Language: fr\\nETag: 123\")",
                                "--auth-type":"AUTH..  HTTP authentication type (Basic, Digest, NTLM or Cert)",
                                "--auth-cred":"AUTH..  HTTP authentication credentials (name:password)",
                                "--auth-cert":"AUTH..  HTTP authentication certificate (key_file,cert_file)",
                                "--proxy":"PROXY       Use a proxy to connect to the target URL",
                                "--proxy-cred":"PRO..  Proxy authentication credentials (name:password)",
                                "--proxy-file":"PRO..  Load proxy list from a file",
                                "--ignore-proxy":"      Ignore system default proxy settings",
                                "--tor":"               Use Tor anonymity network",
                                "--tor-port":"TORPORT  Set Tor proxy port other than default",
                                "--tor-type":"TORTYPE  Set Tor proxy type (HTTP (default), SOCKS4 or SOCKS5)",
                                "--check-tor":"        Check to see if Tor is used properly",
                                "--delay":"DELAY       Delay in seconds between each HTTP request",
                                "--timeout":"TIMEOUT   Seconds to wait before timeout connection (default 30)",
                                "--retries":"RETRIES   Retries when the connection timeouts (default 3)",
                                "--randomize":"RPARAM  Randomly change value for given parameter(s)",
                                "--safe-url":"SAFURL   URL address to visit frequently during testing",
                                "--safe-freq":"SAFREQ  Test requests between two visits to a given safe URL",
                                "--skip-urlencode":"    Skip URL encoding of payload data",
                                "--force-ssl":"         Force usage of SSL/HTTPS",
                                "--hpp":"               Use HTTP parameter pollution",
                                "--eval":"EVALCODE     Evaluate provided Python code before the request (e.g.",
                                "-o":"-o                  Turn on all optimization switches",
                                "--predict-output":"    Predict common queries output",
                                "--keep-alive":"        Use persistent HTTP(s) connections",
                                "--null-connection":"   Retrieve page length without actual HTTP response body",
                                "--threads":"THREADS   Max number of concurrent HTTP(s) requests (default 1)",
                                "-p":"-p TESTPARAMETER    Testable parameter(s)",
                                "--skip":"SKIP         Skip testing for given parameter(s)",
                                "--dbms":"DBMS         Force back-end DBMS to this value",
                                "--dbms-cred":"DBMS..  DBMS authentication credentials (user:password)",
                                "--os":"OS             Force back-end DBMS operating system to this value",
                                "--invalid-bignum":"    Use big numbers for invalidating values",
                                "--invalid-logical":"   Use logical operations for invalidating values",
                                "--no-cast":"           Turn off payload casting mechanism",
                                "--no-escape":"         Turn off string escaping mechanism",
                                "--prefix":"PREFIX     Injection payload prefix string",
                                "--suffix":"SUFFIX     Injection payload suffix string",
                                "--tamper":"TAMPER     Use given script(s) for tampering injection data",
                                "--level":"LEVEL       Level of tests to perform (1-5, default 1)",
                                "--risk":"RISK         Risk of tests to perform (0-3, default 1)",
                                "--string":"STRING     String to match when query is evaluated to True",
                                "--not-string":"NOT..  String to match when query is evaluated to False",
                                "--regexp":"REGEXP     Regexp to match when query is evaluated to True",
                                "--code":"CODE         HTTP code to match when query is evaluated to True",
                                "--text-only":"        Compare pages based only on the textual content",
                                "--titles":"Compare pages based only on their titles",
                                "--technique":"TECH    SQL injection techniques to use (default \"BEUSTQ\")",
                                "--time-sec":"TIMESEC  Seconds to delay the DBMS response (default 5)",
                                "--union-cols":"UCOLS  Range of columns to test for UNION query SQL injection",
                                "--union-char":"UCHAR  Character to use for bruteforcing number of columns",
                                "--union-from":"UFROM  Table to use in FROM part of UNION query SQL injection",
                                "--dns-domain":"DNS..  Domain name used for DNS exfiltration attack",
                                "--second-order":"S..  Resulting page URL searched for second-order response",
                                "-f,":"-f, --fingerprint   Perform an extensive DBMS version fingerprint",
                                "-a,":"-a, --all           Retrieve everything",
                                "-b,":"-b, --banner        Retrieve DBMS banner",
                                "--current-user":"     Retrieve DBMS current user",
                                "--current-db":"        Retrieve DBMS current database",
                                "--hostname":"          Retrieve DBMS server hostname",
                                "--is-dba":"            Detect if the DBMS current user is DBA",
                                "--users":"             Enumerate DBMS users",
                                "--passwords":"         Enumerate DBMS users password hashes",
                                "--privileges":"Enumerate DBMS users privileges",
                                "--roles":"Enumerate DBMS users roles",
                                "--dbs":"Enumerate DBMS databases",
                                "--tables":"Enumerate DBMS database tables",
                                "--columns":"Enumerate DBMS database table columns",
                                "--schema":"Enumerate DBMS schema",
                                "--count":"Retrieve number of entries for table(s)",
                                "--dump":"Dump DBMS database table entries",
                                "--dump-all":"Dump all DBMS databases tables entries",
                                "--search":"Search column(s), table(s) and/or database name(s)",
                                "--comments":"Retrieve DBMS comments",
                                "-D":"DB               DBMS database to enumerate",
                                "-T":"TBL              DBMS database table to enumerate",
                                "-C":"COL              DBMS database table column to enumerate",
                                "-U":"USER             DBMS user to enumerate",
                                "--exclude-sysdbs":"Exclude DBMS system databases when enumerating tables",
                                "--start":"LIMITSTART  First query output entry to retrieve",
                                "--stop":"LIMITSTOP    Last query output entry to retrieve",
                                "--first":"FIRSTCHAR   First query output word character to retrieve",
                                "--last":"LASTCHAR     Last query output word character to retrieve",
                                "--sql-query":"QUERY   SQL statement to be executed",
                                "--sql-shell":"Prompt for an interactive SQL shell",
                                "--sql-file":"SQLFILE  Execute SQL statements from given file(s)",
                                "--common-tables":"Check existence of common tables",
                                "--common-columns":"Check existence of common columns",
                                "User-defined":"User-defined function injection:",
                                "--udf-inject":"Inject custom user-defined functions",
                                "--shared-lib":"SHLIB  Local path of the shared library",
                                "--file-read":"RFILE   Read a file from the back-end DBMS file system",
                                "--file-write":"WFILE  Write a local file on the back-end DBMS file system",
                                "--file-dest":"DFILE   Back-end DBMS absolute filepath to write to",
                                "--os-cmd":"OSCMD      Execute an operating system command",
                                "--os-shell":"Prompt for an interactive operating system shell",
                                "--os-pwn":"Prompt for an OOB shell, meterpreter or VNC",
                                "--os-smbrelay":"One click prompt for an OOB shell, meterpreter or VNC",
                                "--os-bof":"Stored procedure buffer overflow exploitation",
                                "--priv-esc":"Database process user privilege escalation",
                                "--msf-path":"MSFPATH  Local path where Metasploit Framework is installed",
                                "--tmp-path":"TMPPATH  Remote absolute path of temporary files directory",
                                "--reg-read":"Read a Windows registry key value",
                                "--reg-add":"Write a Windows registry key value data",
                                "--reg-del":"Delete a Windows registry key value",
                                "--reg-key":"REGKEY    Windows registry key",
                                "--reg-value":"REGVAL  Windows registry key value",
                                "--reg-data":"REGDATA  Windows registry key value data",
                                "--reg-type":"REGTYPE  Windows registry key value type",
                                "-s":"-s SESSIONFILE      Load session from a stored (.sqlite) file",
                                "-t":"-t TRAFFICFILE      Log all HTTP traffic into a textual file",
                                "--batch":"--batch             Never ask for user input, use the default behaviour",
                                "--charset":"CHARSET   Force character encoding used for data retrieval",
                                "--crawl":"CRAWLDEPTH  Crawl the website starting from the target URL",
                                "--csv-del":"CSVDEL    Delimiting character used in CSV output (default \",\")",
                                "--dump-format":"DU..  Format of dumped data (CSV (default), HTML or SQLITE)",
                                "--eta":"Display for each output the estimated time of arrival",
                                "--flush-session":"Flush session files for current target",
                                "--forms":"Parse and test forms on target URL",
                                "--fresh-queries":"Ignore query results stored in session file",
                                "--hex":"Use DBMS hex function(s) for data retrieval",
                                "--output-dir":"ODIR   Custom output directory path",
                                "--parse-errors":"Parse and display DBMS error messages from responses",
                                "--pivot-column":"P..  Pivot column name",
                                "--save":"Save options to a configuration INI file",
                                "--scope":"SCOPE       Regexp to filter targets from provided proxy log",
                                "--test-filter":"TE..  Select tests by payloads and/or titles (e.g. ROW)",
                                "--update":"Update sqlmap",
                                "-z":"MNEMONICS        Use short mnemonics (e.g. \"flu,bat,ban,tec=EU\")",
                                "--alert":"ALERT       Run shell command(s) when SQL injection is found",
                                "--answers":"ANSWERS   Set question answers (e.g. \"quit=N,follow\")",
                                "--beep":"Make a beep sound when SQL injection is found",
                                "--check-waf":"Heuristically check for WAF/IPS/IDS protection",
                                "--cleanup":"Clean up the DBMS from sqlmap specific UDF and tables",
                                "--dependencies":"Check for missing (non-core) sqlmap dependencies",
                                "--disable-coloring":"Disable console output coloring",
                                "--gpage":"GOOGLEPAGE  Use Google dork results from specified page number",
                                "--identify-waf":"Make a through testing for a WAF/IPS/IDS protection",
                                "--mobile":"Imitate smartphone through HTTP User-Agent header",
                                "--page-rank":"Display page rank (PR) for Google dork results",
                                "--purge-output":"Safely remove all content from output directory",
                                "--smart":"Conduct through tests only if positive heuristic(s)",
                                "--wizard":"Simple wizard interface for beginner users",
                            }
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
        key = key.encode(self.UNICODE_ENCODING)
        retVal = int(hashlib.md5(key).hexdigest()[:12], 16)
        return retVal

    def hashDBRetrieve(self,key, unserialize=False, db=False):
        """
        Helper function for restoring session data from HashDB
        """

        key = "%s%s%s" % (self.url or "%s%s" % (self.hostname, self.port), key, self.HASHDB_MILESTONE_VALUE)
        retVal=""

        hash_ = self.hashKey(key)
        # print "hash_" + str(hash_) + "key=" + key
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

    def base64decode(self,value):
        """
        Decodes string value from Base64 to plain format

        >>> base64decode('Zm9vYmFy')
        'foobar'
        """

        return value.decode("base64")

    def base64encode(self,value):
        """
        Encodes string value from plain to Base64 format

        >>> base64encode('foobar')
        'Zm9vYmFy'
        """

        return value.encode("base64")[:-1].replace("\n", "")

    def base64unpickle(self,value):
        """
        Decodes value from Base64 to plain format and deserializes (with pickle) its content

        >>> base64unpickle('gAJVBmZvb2JhcnEALg==')
        'foobar'
        """
        if value:
            return pickle.loads(self.base64decode(value))


    def xmlvalue(self,db,name,value="query"):

        filepath = "%s" % os.path.join(current_path, "plugins/repo/sqlmap/queries.xml")
        with open(filepath,"r") as f:
            try:
                tree = ET.fromstring(f.read())
            except SyntaxError, err:
                print "SyntaxError: %s. %s" % (err, filepath)
                return None

        for node in tree.findall("dbms[@value='"+db+"']/"+name+""):
            return node.attrib[value]

    def getuser(self,data):
        users = re.findall('database management system users \[[\d]+\]:\r\n(.*?)\r\n\r\n',data, re.S)
        if users:
            return map((lambda x: x.replace("[*] ","")), users[0].split("\r\n"))

    def getdbs(self,data):
        dbs = re.findall('available databases \[[\d]+\]:\r\n(.*?)\r\n\r\n',data, re.S)
        if dbs:
            return map((lambda x: x.replace("[*] ","")), dbs[0].split("\r\n"))
    def getpassword(self,data):
        users={}
        password = re.findall('database management system users password hashes:\r\n(.*?)\r\n\r\n',data, re.S)
        if password:
            for p in password[0].split("[*] ")[1::]:

                user=re.findall("^(.*?) \[",p)[0]
                mpass=re.findall("password hash: (.*?)$",p, re.S)
                mpass=map((lambda x: re.sub(r"[ \r\n]", "", x)), mpass[0].split("password hash: "))
                users[user]=mpass
        return users

    def getAddress(self, hostname):
        """
        Returns remote IP address from hostname.
        """
        try:
            return socket.gethostbyname(hostname)
        except socket.error, msg:

            return self.hostname

    def parseOutputString(self, output, debug = False):
        """
        This method will discard the output the shell sends, it will read it from
        the xml where it expects it to be present.

        NOTE: if 'debug' is true then it is being run from a test case and the
        output being sent is valid.
        """

        sys.path.append(self.getSetting("Sqlmap path"))

        from lib.core.settings import HASHDB_MILESTONE_VALUE
        from lib.core.enums import HASHDB_KEYS
        from lib.core.settings import UNICODE_ENCODING
        self.HASHDB_MILESTONE_VALUE = HASHDB_MILESTONE_VALUE
        self.HASHDB_KEYS = HASHDB_KEYS
        self.UNICODE_ENCODING = UNICODE_ENCODING

        password = self.getpassword(output)
        webserver = re.search("web application technology: (.*?)\n",output)
        if webserver:
            webserver=webserver.group(1)
        users = self.getuser(output)
        # print users
        dbs = self.getdbs(output)

        # print "webserver = " + webserver
        # print "dbs = " + str(dbs)
        # print "users = " + str(users)
        # print "password = " + str(password)


        db = Database(self._output_path)
        db.connect()

        absFilePaths = self.hashDBRetrieve(self.HASHDB_KEYS.KB_ABS_FILE_PATHS, True, db)
        tables = self.hashDBRetrieve(self.HASHDB_KEYS.KB_BRUTE_TABLES, True, db)
        columns = self.hashDBRetrieve(self.HASHDB_KEYS.KB_BRUTE_COLUMNS, True, db)
        xpCmdshellAvailable = self.hashDBRetrieve(self.HASHDB_KEYS.KB_XP_CMDSHELL_AVAILABLE, True, db)
        dbms_version = self.hashDBRetrieve(self.HASHDB_KEYS.DBMS, False, db)

        os = self.hashDBRetrieve(self.HASHDB_KEYS.OS, False, db)

        self.ip=self.getAddress(self.hostname)

        dbms=str(dbms_version.split(" ")[0])

        h_id = self.createAndAddHost(self.ip)
        i_id = self.createAndAddInterface(h_id, name=self.ip, ipv4_address=self.ip,hostname_resolution=self.hostname)
        s_id = self.createAndAddServiceToInterface(h_id, i_id, self.protocol,
                                            "tcp",
                                            [self.port],
                                            status="open",
                                            version=webserver)
        n_id = self.createAndAddNoteToService(h_id,s_id,"website","")
        n2_id = self.createAndAddNoteToNote(h_id,s_id,n_id,self.hostname,"")

        db_port=self.db_port[dbms]

        s_id2 = self.createAndAddServiceToInterface(h_id, i_id,
                                                    name=dbms ,
                                                    protocol="tcp",
                                                    status="down",
                                                    version=str(dbms_version),
                                                    ports=[str(db_port)],
                                                    description="DB detect by SQLi")
        if users:
            for v in users:
                self.createAndAddCredToService(h_id,s_id2,v,"")

        if password:
            for k,v in password.iteritems():
                for p in v:
                    self.createAndAddCredToService(h_id,s_id2,k,p)

        if absFilePaths:
            n_id2 = self.createAndAddNoteToService(h_id,s_id2,"sqlmap.absFilePaths",str(absFilePaths))
        if tables:
            n_id2 = self.createAndAddNoteToService(h_id,s_id2,"sqlmap.brutetables",str(tables))
        if columns:
            n_id2 = self.createAndAddNoteToService(h_id,s_id2,"sqlmap.brutecolumns",str(columns))
        if xpCmdshellAvailable:
            n_id2 = self.createAndAddNoteToService(h_id,s_id2,"sqlmap.xpCmdshellAvailable",str(xpCmdshellAvailable))

        for inj in self.hashDBRetrieve(self.HASHDB_KEYS.KB_INJECTIONS, True,db) or []:
            # print inj
            # print inj.dbms
            # print inj.dbms_version
            # print inj.place
            # print inj.os
            # print inj.parameter

            dbversion = self.hashDBRetrieve("None"+self.xmlvalue(dbms,"banner"), False, db)
            user = self.hashDBRetrieve("None"+self.xmlvalue(dbms,"current_user"), False, db)
            dbname = self.hashDBRetrieve("None"+self.xmlvalue(dbms,"current_db"), False, db)
            hostname = self.hashDBRetrieve("None"+self.xmlvalue(dbms,"hostname"), False, db)

            # print "username = " + user

            if user:
                n_id2 = self.createAndAddNoteToService(h_id,s_id2,"db.user",user)
            if dbname:
                n_id2 = self.createAndAddNoteToService(h_id,s_id2,"db.name",dbname)
            if hostname:
                n_id2 = self.createAndAddNoteToService(h_id,s_id2,"db.hostname",hostname)
            if dbversion:
                n_id2 = self.createAndAddNoteToService(h_id,s_id2,"db.version",dbversion)
            if dbs:
                n_id2 = self.createAndAddNoteToService(h_id,s_id2,"db.databases",str(dbs))

            for k,v in inj.data.items():
                v_id = self.createAndAddVulnWebToService(h_id, s_id,
                                                         website=self.hostname,
                                                         name=inj.data[k]['title'],
                                                         desc="Payload:" + str(inj.data[k]['payload'])+
                                                        "\nVector:"+ str(inj.data[k]['vector'])+
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
            args, unknown = parser.parse_known_args(shlex.split(re.sub(r'\-h|\-\-help', r'', command_string)))
        except SystemExit:
            pass

        if args.r:
            with open(args.r, 'r') as f:
                request = self.HTTPRequest(f.read())
                args.u="http://"+request.headers['host']+ request.path
                f.close()

        if args.u:
            reg = re.search("(http|https|ftp)\://([a-zA-Z0-9\.\-]+(\:[a-zA-Z0-9\.&amp;%\$\-]+)*@)*((25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9])|localhost|([a-zA-Z0-9\-]+\.)*[a-zA-Z0-9\-]+\.(com|edu|gov|int|mil|net|org|biz|arpa|info|name|pro|aero|coop|museum|[a-zA-Z]{2}))[\:]*([0-9]+)*([/]*($|[a-zA-Z0-9\.\,\?\'\\\+&amp;%\$#\=~_\-]+)).*?$", args.u)
            self.protocol = reg.group(1)
            self.hostname = reg.group(4)
            self.path ="/"
            if self.protocol == 'https':
                self.port=443
            if reg.group(11) is not None:
                self.port = reg.group(11)

            if reg.group(12) is not None:
                tmp=re.search("/(.*)\?(.*?$)",reg.group(12))
                self.path = "/"+tmp.group(1)
                self.params=tmp.group(2)

            self.url=self.protocol+"://"+self.hostname+":"+self.port + self.path
            self.fullpath=self.url+"?"+self.params
            self._output_path="%s%s" % (os.path.join(self.data_path, "sqlmap_output-"),
                                        re.sub(r'[\n\/]', r'', args.u.encode("base64")[:-1]))

        if not args.s:
            return "%s -s %s" % (command_string,self._output_path)


    def setHost(self):
        pass


def createPlugin():
    return SqlmapPlugin()
