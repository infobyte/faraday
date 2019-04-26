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
from faraday.client.persistence.server import models, server
from faraday.client.persistence.server.server import SERVER_URL

__description__ = 'Script to perform a brute force attack on different services in a workspace'
__prettyname__ = 'FBrute'

SUPPORTED_SERVICES = ["asterisk", "cisco", "cisco-enable", "cvs", "firebird", "ftp", "ftps", "http",
                      "https", "http-proxy", "icq" "imap", "imaps", "irc", "ldap2", "ldap3",
                      "mssql", "mysql", "nntp", "oracle-listener", "oracle-sid", "pcanywhere",
                      "pcnfs", "pop3", "pop3s", "postgres", "rdp", "redis", "rexec", "rlogin",
                      "rsh", "rtsp", "s7-300", "sip", "smb", "smtp", "smtps", "smtp-enum", "snmp",
                      "socks5", "ssh", "sshkey", "svn", "teamspeak", "telnet"
                      "telnets", "vmauthd", "vnc", "xmpp"]

PID = os.getpid()

def check_hydra():
    p = Popen(["which", "hydra"], stdout=PIPE)
    p.communicate()[0]
    return p.returncode == 0


def add_output(output):
    pwd = os.getcwd()
    data = {"cmd" : base64.b64encode(output), "pid" : PID, "pwd" : base64.b64encode(pwd)}
    requests.post("http://localhost:9977/cmd/input", json=data)


def send_output(output):
    output = base64.b64encode(open(output, "r").read())
    data = {"exit_code" : 0, "pid" : PID, "output" : output}
    requests.post("http://localhost:9977/cmd/output", json=data)


def search_hosts_by_service(workspace, b_service):
    output = ""
    all_hosts = list(models.get_hosts(workspace))
    all_services = list(models.get_services(workspace))
    for host in all_hosts:
        for service in all_services:
            id_service_host = service.parent_id
            if host.id == id_service_host and service.name == b_service:
                output += host.name + "\n"
                break
    return output


def total_credentials(workspace):
    json_creds = server._get(
        SERVER_URL + "/_api/v2/ws/%s/credential" % workspace)

    return len(json_creds["rows"])


def get_credentials(workspace, key):
    credentials = ""

    json_creds = server._get(
        SERVER_URL + "/_api/v2/ws/%s/credential" % workspace)

    if len(json_creds["rows"]) > 0:

        for c in json_creds["rows"]:
            credentials += c["value"][key] + "\n"
        return credentials

    else:
        sys.exit("No credentials were found on faraday")


def show_table_services(workspace):

    services = []
    table = ""

    j_parsed = server._get(
        SERVER_URL + "/_api/v2/ws/%s/services/count?group_by=name" % workspace)

    if len(j_parsed["groups"]) > 0:

        table += "Number\tService\tCount\n"
        table += "------\t-------\t------\n"

        for l in j_parsed["groups"]:
            if l["name"] in SUPPORTED_SERVICES:
                services.append(l["name"])
                table += "[" + str(services.index(l["name"])) + "]\t"
                table += l["name"] + "\t" + str(l["count"]) + "\n"
        return table, services

    else:
        sys.exit("No services availables")


def input_index(text, leng):
    while 1:

        stdin = raw_input(text+"[0-"+str(leng-1)+"/q]: ")

        if re.search("[0-9]", stdin) is not None:

            if int(stdin) > leng-1 or int(stdin) < 0:
                continue

            else:
                return stdin

        elif stdin == "q":
            sys.exit(1)

        else:
            continue


def show_options(workspace):

    user_define_dictionary = False
    usernames_dic_path = None
    passwords_dic_path = None
    user_faraday = None
    passwd_faraday = None

    # Muestro los servicios en el workspace soportados por hydra, en formato tabla
    table_services, services = show_table_services(workspace)
    print(table_services)

    service = int(input_index("What service do you want to bruteforce?", len(services)))

    # Verifico si el usuario quiere armar un diccionario con las credenciales
    # guardadas en faraday o si quiere utilizar uno propio
    print("\n[0] Choose a dictionary")
    print("[1] Create dictionary from Faraday (based in credentials stored in Faraday)\n")

    dictionary = int(input_index("Options ", 2))

    #Le pido el path de el user dic y el password dic
    if dictionary == 0:
        usernames_dic_path = raw_input("Usernames file: ")
        passwords_dic_path = raw_input("Passwords file: ")
        user_define_dictionary = True

    else:

        print("\n[*] Obtaining credentials from the workspace %s" % workspace)

        user_faraday = save_targets(get_credentials(workspace, "username"))
        passwd_faraday = save_targets(get_credentials(workspace, "password"))

        print("[*] Credentials found: %s" % total_credentials(workspace))
        print("\nUsername\t\tPassword")
        print("--------\t\t--------")

        for user, passw in zip(
                open(user_faraday, "r"), open(passwd_faraday, "r")):

            print("%s\t\t%s" % (user.strip(), passw.strip()))


    return service, services, user_define_dictionary, user_faraday, passwd_faraday, usernames_dic_path, passwords_dic_path


def save_targets(output):

    dicc = "/tmp/targets_"+str(time.time())

    f = open(dicc, "w")
    f.write(output)
    f.close()

    return dicc


def main(workspace='', args=None, parser=None):

    print("\nThis script needs to be run inside from Faraday GTK.\n")
    if check_hydra():

        service, services, user_define_dictionary, user_faraday, passwd_faraday, usernames_dic_path, passwords_dic_path = show_options(workspace)

        b_service = services[service]
        output = search_hosts_by_service(workspace, b_service)
        targets = save_targets(output)

        hydra_output = "/tmp/hydra_output-%s.txt" % time.time()

        print("Running Hydra, please wait to finish the bruteforce...\n")

        if user_define_dictionary:

            hydra_command1 = "hydra -L {0} -P {1} -e sr -M {2} -V -q {3} -o {4}".format(
                usernames_dic_path,
                passwords_dic_path,
                targets,
                b_service,
                hydra_output)

            add_output(hydra_command1)
            call(shlex.split(hydra_command1))

        else:
            hydra_command2 = "hydra -L {0} -P {1}  -e sr -M {2} -V -q {3} -o {4}".format(
                user_faraday,
                passwd_faraday,
                targets,
                b_service,
                hydra_output)

            add_output(hydra_command2)
            call(shlex.split(hydra_command2))

        print("Processing information found in Faraday...\n")
        send_output(hydra_output)

        return None, None

    else:
        sys.exit("Hydra is not installed on the system. Install hydra to continue execution")
        return None, None
