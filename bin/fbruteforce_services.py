#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2018  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import os
import sys
import base64
import shlex
import time
import re
import requests

from subprocess import Popen, PIPE, call
from persistence.server import models, server
from persistence.server.server import SERVER_URL

__description__ = 'Script to perform a brute force attack on different services in a workspace'
__prettyname__ = 'FBrute'

SUPPORTED_SERVICES = ["asterisk", "cisco", "cisco-enable", "cvs", "firebird", "ftp", "ftps", "http", "https", "http-proxy",
                      "icq" "imap", "imaps", "irc", "ldap2", "ldap3", "mssql", "mysql", "nntp", "oracle-listener", "oracle-sid",
                      "pcanywhere", "pcnfs", "pop3", "pop3s", "postgres", "rdp", "redis", "rexec", "rlogin", "rsh", "rtsp", "s7-300",
                      "sip", "smb", "smtp", "smtps", "smtp-enum", "snmp", "socks5", "ssh", "sshkey", "svn", "teamspeak", "telnet",
                      "telnets", "vmauthd", "vnc", "xmpp"]
PID = os.getpid()

def checkHydra():
    p = Popen(["which", "hydra"], stdout=PIPE)
    p.communicate()[0]
    return p.returncode == 0


def addOutput(output):
    pwd = os.getcwd()
    data = {"cmd" : base64.b64encode(output), "pid" : PID, "pwd" : base64.b64encode(pwd)}
    requests.post("http://localhost:9977/cmd/input", json=data)


def sendOutput(output):
    output = base64.b64encode(open(output, "r").read())
    data = {"exit_code" : 0, "pid" : PID, "output" : output}
    requests.post("http://localhost:9977/cmd/output", json=data)


def searchHostsByService(workspace, b_service):
    output = ""
    for hosts in models.get_hosts(workspace):
        for services in models.get_services(workspace):
            id_service_host = services.parent_id
            if hosts.id == id_service_host and services.name == b_service:
                output += hosts.name
                break
    return output


def totalCredentials(workspace):
    json_creds = server._get(SERVER_URL + "/_api/v2/ws/%s/credential" % workspace)
    return len(json_creds["rows"])


def getCredentials(workspace, key):
    credentials = ""
    json_creds = server._get(SERVER_URL + "/_api/v2/ws/%s/credential" % workspace)
    if len(json_creds["rows"]) > 0:
        for c in json_creds["rows"]:
            credentials += c["value"][key]+"\n"
        return credentials
    else:
        sys.exit("No credentials were found on faraday")


def showTableServices(workspace):
    global services
    services = []
    table = ""
    j_parsed = server._get(SERVER_URL + "/_api/v2/ws/%s/services/count?group_by=name" % workspace)
    if len(j_parsed["groups"]) > 0:
        table += "Number\tService\tCount\n"
        table += "------\t-------\t------\n"
        for l in j_parsed["groups"]:
            if l["name"] in SUPPORTED_SERVICES:
                services.append(l["name"])
                table += "[" + str(services.index(l["name"])) + "]\t" + l["name"] + "\t" + str(l["count"]) + "\n"
        return table
    else:
        sys.exit("No services availables")


def inputIndex(text, leng):
    while 1:
        stdin = raw_input(text+"[0-"+str(leng-1)+"/q]: ")
        if re.search("[0-9]", stdin) is not None:
            if int(stdin) > leng-1 or int(stdin) < 0:
                continue
            else:
                return stdin
                break
        elif stdin == "q":
            sys.exit(1)
        else:
            continue


def showOptions(workspace):
    global service
    global dict
    global user_faraday
    global passwd_faraday
    global usernames_dic_path
    global passwords_dic_path

    # Muestro los servicios en el workspace soportados por hydra, en formato tabla
    print showTableServices(workspace)

    service = int(inputIndex("What service do you want to bruteforce?", len(services)))

    # Verifico si el usuario quiere armar un diccionario con las credenciales
    # guardadas en faraday o si quiere utilizar uno propio
    print "\n[0] Choose a dictionary"
    print "[1] Create dictionary from Faraday (based in credentials stored in Faraday)\n"

    dictionary = int(inputIndex("Options ", 2))

    if dictionary == 0:
        usernames_dic_path = raw_input("Usernames file: ")
        passwords_dic_path = raw_input("Passwords file: ")
        dict = True

        #Le pido el path de el user dic y el password dic
    else:
        print "\n[*] Obtaining credentials from the workspace %s" % workspace
        user_faraday = saveTargets(getCredentials(workspace, "username"))
        passwd_faraday = saveTargets(getCredentials(workspace, "password"))
        print "[*] Credentials found: %s" % totalCredentials(workspace)
        print "\nUsername\t\tPassword"
        print "--------\t\t--------"
        for user, passw in zip(open(user_faraday, "r"), open(passwd_faraday, "r")):
            print  "%s\t\t%s" % (user.strip(), passw.strip())


def saveTargets(output):
    dicc = "/tmp/targets_"+str(time.time())
    f = open(dicc, "w")
    f.write(output)
    f.close()
    return dicc


def main(workspace='', args=None, parser=None):

    print "\nThis script need to be run inside from Faraday GTK.\n"
    if checkHydra():

        showOptions(workspace)

        b_service = services[service]
        output = searchHostsByService(workspace, b_service)
        targets = saveTargets(output)

        hydra_output = "/tmp/hydra_output-%s.txt" % time.time()

        print "Running Hydra, please wait to finish the bruteforce...\n"

        if dict is True:

            hydra_command1 = "hydra -L {0} -P {1} -e sr -M {2} -V -q {3} -o {4}".format(
                usernames_dic_path,
                passwords_dic_path,
                targets,
                b_service,
                hydra_output)

            addOutput(hydra_command1)
            call(shlex.split(hydra_command1))

        else:
            hydra_command2 = "hydra -L {0} -P {1}  -e sr -M {2} -V -q {3} -o {4}".format(
                user_faraday,
                passwd_faraday,
                targets,
                b_service,
                hydra_output)

            addOutput(hydra_command2)
            call(shlex.split(hydra_command2))

        print "Processing information found in Faraday...\n"
        sendOutput(hydra_output)
        return None, None
    else:
        sys.exit("Hydra is not installed on the system. Install hydra to continue execution")
        return None, None
