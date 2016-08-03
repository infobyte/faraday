#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from __future__ import with_statement
from plugins import core
from model import api
import re
import os
import sys

try:
    import psycopg2
except ImportError:
    raise Exception("Please install psycopg2 to use plugin: MetasploitOn")

import time

current_path = os.path.abspath(os.getcwd())

__author__ = "Francisco Amato"
__copyright__ = "Copyright (c) 2013, Infobyte LLC"
__credits__ = ["Francisco Amato"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "Francisco Amato"
__email__ = "famato@infobytesec.com"
__status__ = "Development"


class MetasploitOnPlugin(core.PluginBase):
    """
    Example plugin to parse metasploiton output.
    """

    def __init__(self):

        core.PluginBase.__init__(self)
        self.id = "MetasploitOn"
        self.name = "Metasploit Online Service Plugin"
        self.plugin_version = "0.0.3"
        self.version = "Metasploit 4.10.0"
        self.framework_version = "1.0.0"
        self.options = None
        self._current_output = None
        self.target = None
        self._command_regex = re.compile(
            r'^(metasploiton|sudo metasploiton|\.\/metasploiton).*?')

        global current_path

        self.addSetting("Database", str, "db")
        self.addSetting("User", str, "user")
        self.addSetting("Password", str, "pass")
        self.addSetting("Server", str, "localhost")
        self.addSetting("Port", str, "5432")
        ### NOTE: do _not_ correct the typo, it's used by the user.xml
        self.addSetting("Wordspace", str, "a_workspace")
        self.addSetting("Enable", str, "0")

        self._sdate = ""
        self._lsdate = ""
        self._mwhere = ""

    def parseOutputString(self, output, debug=False):
        """
        This method will discard the output the shell sends, it will read it
        from the xml where it expects it to be present.

        NOTE: if 'debug' is true then it is being run from a test case and the
        output being sent is valid.
        """

        try:
            conn = psycopg2.connect(dbname=self.getSetting("Database"),
                                    user=self.getSetting("User"),
                                    password=self.getSetting("Password"),
                                    host=self.getSetting("Server"),
                                    port=self.getSetting("Port"))

            # conn = psycopg2.connect("dbname='" + self.getSetting("Database") +
            #                         "' user='" + self.getSetting("User") +
            #                         "' password='" + self.getSetting("Password") +
            #                         "' host='" + self.getSetting("Server") +
            #                         "' port='" + self.getSetting("Port") +
            #                         "'")

            cur = conn.cursor()
        except Exception as e:
            print e
            print "Error Connecting to the database\n"
            return

        cur = self._doSql(
            cur,
            "select * from hosts inner join workspaces ON (hosts.workspace_id=workspaces.id) where workspaces.name like '" + self.getSetting("Wordspace") + "';")
        if cur is None:
            print "Error getting database data\n"
            return

        self.path = self.data_path + "/" + api.getActiveWorkspace().name + \
            "_metasploit_last"

        if os.path.isfile(self.path):
            f = open(self.path, "r")
            self._sdate = f.readline()
            f.close

        for h in cur.fetchall():

            h_id = self.createAndAddHost(
                str(h[2]),
                str(h[7]))

            if self._isIPV4(str(h[2])):

                i_id = self.createAndAddInterface(
                    h_id,
                    str(h[2]),
                    mac=str(h[3]),
                    ipv4_address=str(h[2]),
                    hostname_resolution=str(h[5]))
            else:

                i_id = self.createAndAddInterface(
                    h_id,
                    str(h[2]),
                    mac=str(h[3]),
                    ipv6_address=str(h[2]),
                    hostname_resolution=str(h[5]))

            self._checkDate(str(h[13]))

            cur = self._doSql(
                cur,
                "select * from vulns where host_id=" + str(h[0]) + " and service_id is null" + self._mwhere + ";")
            if cur is None:
                return

            for v in cur.fetchall():

                self._checkDate(str(v[5]))

                cur = self._doSql(
                    cur,
                    "select * from vulns_refs inner join refs ON (vulns_refs.id=refs.id) where vulns_refs.vuln_id=" + str(v[0]) + ";")
                if cur is None:
                    return

                refs = []
                for r in cur.fetchall():
                    self._checkDate(str(r[5]))
                    refs.append(r[6])

                self.createAndAddVulnToHost(
                    h_id,
                    str(v[4]),
                    str(v[6]),
                    refs)

            cur = self._doSql(
                cur,
                "select * from notes where host_id=" + str(h[0]) + " and service_id is null" + self._mwhere + ";")
            if cur is None:
                return

            for n in cur.fetchall():
                self._checkDate(str(n[6]))
                self.createAndAddNoteToHost(
                    h_id,
                    str(n[2]),
                    str(n[9]))

            cur = self._doSql(
                cur,
                "select * from services where host_id=" + str(h[0]))
            if cur is None:
                return

            for s in cur.fetchall():

                self._checkDate(str(s[7]))
                s_id = self.createAndAddServiceToInterface(
                    h_id,
                    i_id,
                    name=str(s[6]),
                    ports=[str(s[3])],
                    protocol=str(s[4]),
                    status=str(s[5]),
                    description=str(s[8]),
                    version=str(s[8]))

                cur = self._doSql(
                    cur,
                    "select * from creds where service_id=" + str(s[0]) + self._mwhere + ";")

                if cur is None:
                    return
                for c in cur.fetchall():
                    self._checkDate(str(c[3]))

                    self.createAndAddCredToService(
                        h_id,
                        s_id,
                        c[4],
                        c[5])

                    self.createAndAddVulnToService(
                        h_id,
                        s_id,
                        "Weak Credentials",
                        "[metasploit found the following credentials]\nuser:%s\npass:%s" % (c[4], c[
                                                                                            5]),
                        severity="high")

                cur = self._doSql(
                    cur,
                    "select * from vulns where host_id=" + str(h[0]) + " and service_id=" + str(s[0]) + self._mwhere + ";")
                if cur is None:
                    return

                for v in cur.fetchall():
                    self._checkDate(str(v[5]))

                    cur = self._doSql(
                        cur,
                        "select * from vulns_refs inner join refs ON (vulns_refs.id=refs.id) where vulns_refs.vuln_id=" + str(v[0]) + ";")
                    if cur is None:
                        return

                    refs = []
                    for r in cur.fetchall():
                        self._checkDate(str(r[5]))
                        refs.append(r[6])

                    self.createAndAddVulnToService(
                        h_id,
                        s_id,
                        name=str(v[4]),
                        desc=str(v[6]),
                        ref=refs)

                mwhere = re.sub(
                    "updated_at",
                    "web_vulns.updated_at",
                    self._mwhere)

                cur = self._doSql(
                    cur,
                    "select * from web_vulns INNER JOIN web_sites ON (web_vulns.web_site_id=web_sites.id) where web_sites.service_id=" + str(s[0]) + mwhere + ";")

                if cur is None:
                    return


                for v in cur.fetchall():
                    self._checkDate(str(v[3]))

                    #TODO: should be nice to stop hardcoding the positions
                    # of the information and instead make it depend
                    # on the column name

                    # beware, next silly coder, the table as it stands
                    # right holds information in each position like this:
                    # v[0] = id, v[1] = web_site_id, v[2] = created_at
                    # v[3] = updated_at, v[4] = path, v[5] = method,
                    # v[6] = params, v[7] = pname, v[8] = risk, v[9] = name
                    # v[10] = query, v[11] = category, v[12] = confidence,
                    # v[13] = description, v[14] = blame, v[15] = request,
                    # v[16] = proof, v[17] = owner, v[18] = payload, v[19] = id,
                    # v[20] = service_id, v[21] = created_at, v[22] = updated_at
                    # v[23] = vhost, v[24] = comments, v[25] = options

                    # if the plugin breakes, check that everything is in the
                    # same position

                    # metasploit doesn't give us a website, but the vhost +
                    # path is kinda the same
                    website = str(v[23]) + str(v[4])

                    self.createAndAddVulnWebToService(
                        h_id,
                        s_id,
                        name=str(v[9]),
                        desc=str(v[13]),
                        website=website,
                        path=str(v[5]),
                        request=str(v[16]),
                        method=str(v[6]),
                        pname=str(v[8]),
                        params=str(v[7]),
                        query=str(v[11]))

                cur = self._doSql(
                    cur,
                    "select * from notes where host_id=" + str(h[0]) + " and service_id=" + str(s[0]) + self._mwhere)

                if cur is None:
                    return

                for n in cur.fetchall():

                    self._checkDate(str(n[6]))

                    self.createAndAddNoteToService(
                        h_id,
                        s_id,
                        str(n[2]),
                        str(n[9]))

                cur = self._doSql(
                    cur,
                    "select * from web_sites where service_id=" + str(s[0]) + self._mwhere)

                for w in cur.fetchall():

                    self._checkDate(str(w[3]))

                    n_id = self.createAndAddNoteToService(
                        h_id,
                        s_id,
                        "website",
                        "")

                    n2_id = self.createAndAddNoteToNote(
                        h_id,
                        s_id,
                        n_id,
                        str(w[4]),
                        "")

        cur.close()
        conn.close()

    def _doSql(self, db, sql):
        try:
            api.devlog("SQL:" + sql)
            db.execute(sql)
        except Exception, e:
            print ("Error SQL[" + e.pgcode + "] - " + e.pgerror)
            return None

        return db

    def _checkDate(self, rowdate):

        mret = True
        msave = True

        if not self._lsdate:

            if self._sdate:
                self._lsdate = self._sdate
            else:
                self._lsdate = rowdate

        if self._cdate(self._lsdate, rowdate):
            msave = False

        if self._sdate:
            self._mwhere = " and updated_at > to_timestamp('" + \
                self._sdate + "','YYYY-MM-DD HH24:MI:SS.US');"

        if msave:
            try:
                f = open(self.path, "w")
                f.write(rowdate)
                f.close()
                self._lsdate = rowdate
            except:
                print ("Can't save metasploit lastupdate file")
                return

        return mret

    def _cdate(self, date1, date2):

        mdate = time.strptime(date1.split(".")[0], "%Y-%m-%d %H:%M:%S")
        mdate2 = time.strptime(date2.split(".")[0], "%Y-%m-%d %H:%M:%S")

        if mdate > mdate2:
            return True
        else:
            return False

    def _isIPV4(self, ip):
        if len(ip.split(".")) == 4:
            return True
        else:
            return False

    def processCommandString(self, username, current_path, command_string):
        return None

    def setHost(self):
        pass


def createPlugin():
    return MetasploitOnPlugin()

if __name__ == '__main__':
    parser = MetasploitOnXmlParser(sys.argv[1])
    for item in parser.items:
        if item.status == 'up':
            print item
