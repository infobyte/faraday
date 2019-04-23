'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
             
class Modelactions:
    ADDHOST = 2000
    DELHOST = 2001
    ADDSERVICEHOST = 2008
    ADDSERVICEHOST = 20008
    ADDCATEGORY = 2011  # TODO migration: check why isn't implemented
    ADDVULNHOST = 2017
    DELVULNHOST = 2018
    ADDVULNSRV = 2019
    DELVULNSRV = 2020
    ADDNOTEHOST = 2025
    DELNOTEHOST = 2026
    ADDNOTESRV = 2027
    DELNOTESRV = 2028
    RENAMEROOT = 2029  # TODO migration: check why isn't implemented
    ADDNOTEVULN = 2030
    DELNOTEVULN = 2031  # TODO migration: check why isn't implemented
    EDITHOST = 2032
    EDITSERVICE = 2035
    ADDCREDSRV = 2036
    DELCREDSRV = 2037
    ADDVULNWEBSRV = 2038
    DELVULNWEBSRV = 2039  # TODO migration: check why isn't implemented
    ADDNOTENOTE = 2040
    DELNOTENOTE = 2041  # TODO migration: check why isn't implemented
    EDITNOTE = 2042
    EDITVULN = 2043
    ADDNOTE = 2044
    DELNOTE = 2045
    ADDVULN = 2046
    DELVULN = 2047
    EDITCRED = 2048
    ADDCRED = 2049
    DELCRED = 2050
    PLUGINSTART = 3000
    PLUGINEND = 3001
    LOG = 3002
    DEVLOG = 3003

    __descriptions = {
        ADDHOST: "ADDHOST",
        DELHOST: "DELHOST",
        ADDCATEGORY: "ADDCATEGORY",
        ADDVULNHOST: "ADDVULNHOST",
        DELVULNHOST: "DELVULNHOST",
        ADDVULNSRV: "ADDVULNSRV",
        DELVULNSRV: "DELVULNSRV",
        ADDNOTEVULN: "ADDNOTEVULN",
        DELNOTEVULN: "DELNOTEVULN",
        ADDNOTENOTE: "ADDNOTENOTE",
        DELNOTENOTE: "DELNOTENOTE",
        EDITHOST: "EDITHOST",
        ADDCREDSRV: "ADDCREDSRV",
        DELCREDSRV: "DELCREDSRV",
        ADDVULNWEBSRV: "ADDVULNSWEBRV",
        DELVULNWEBSRV: "DELVULNWEBSRV",
        EDITNOTE: "EDITNOTE",
        EDITVULN: "EDITVULN",
        EDITCRED: "EDITCRED",
        ADDNOTE: "ADDNOTE",
        DELNOTE: "DELNOTE",
        ADDVULN: "ADDVULN",
        DELVULN: "DELVULN",
        ADDCRED: "ADDCRED",
        DELCRED: "DELCRED",
        PLUGINSTART: "PLUGINSTART",
        PLUGINEND: "PLUGINEND"
    }

    @staticmethod
    def getDescription(action):
        return modelactions.__descriptions.get(action, "")