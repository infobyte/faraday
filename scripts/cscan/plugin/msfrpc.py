#!/usr/bin/env python2

import os
import time
import string
import random
import argparse
import msgpack
import httplib
import ssl


class Msfrpc:
    """ Msfrpc class from https://github.com/SpiderLabs/msfrpc """

    class MsfError(Exception):
        def __init__(self, msg):
            self.msg = msg

        def __str__(self):
            return repr(self.msg)

    class MsfAuthError(MsfError):
        def __init__(self, msg):
            self.msg = msg

    def __init__(self, opts=[]):
        self.host = opts.get("host") or "127.0.0.1"
        self.port = opts.get("port") or 55552
        self.uri = opts.get("uri") or "/api/"
        self.ssl = opts.get("ssl") or False
        self.authenticated = False
        self.token = False
        self.headers = {"Content-type": "binary/message-pack"}
        if self.ssl:
            self.client = httplib.HTTPSConnection(self.host, self.port, context=ssl._create_unverified_context())
        else:
            self.client = httplib.HTTPConnection(self.host, self.port)

    def encode(self, data):
        return msgpack.packb(data)

    def decode(self, data):
        return msgpack.unpackb(data)

    def call(self, meth, opts=[]):
        if meth != "auth.login":
            if not self.authenticated:
                raise self.MsfAuthError("MsfRPC: Not Authenticated")
            opts.insert(0, self.token)

        opts.insert(0, meth)
        params = self.encode(opts)
        self.client.request("POST", self.uri,params, self.headers)
        resp = self.client.getresponse()
        return self.decode(resp.read())

    def login(self, user, password):
        ret = self.call("auth.login", [user, password])
        if ret.get("result") == "success":
            self.authenticated = True
            self.token = ret.get("token")
            return True
        else:
            raise self.MsfAuthError("MsfRPC: Authentication failed")


class CscanMsf:
    """ msfrpc plugin for cscan """
    def __init__(self, client, logfile=False, quiet=False):
        self.logfile = logfile
        self.cid = None
        self.quiet = quiet
        self.client = client

    def check_auth(self):
        if not self.client or not self.client.authenticated:
            self.log("ERROR: You are not authenticated..", True)
            return False
        return True

    def log(self, msg, critical=False):
        if self.logfile:
            logfile = open(self.logfile, "a")
            logfile.write("%s\n" % msg)
            logfile.close()
        if not self.quiet or critical:
            print msg

    def rpc_call(self, meth, opts, key=""):
        if self.check_auth():
            res = self.client.call(meth, opts)

            if "error" in res:
                self.log("ERROR: %s %s" % (res.get("error_code"), res.get("error_message")), True)
                self.log("%s: %s\n%s" % (res.get("error_class"), res.get("error_string"), res.get("error_backtrace")))
                return res
            return res if not key else res.get(key)

    def create_console(self):
        self.cid = self.rpc_call("console.create", [{}], "id")
        self.rpc_call("console.read", [self.cid])
        self.log("Created console ID " + str(self.cid), True)
        return self.cid

    def destroy_console(self):
        self.log("Destroy console ID %s.. %s" % (self.cid, self.rpc_call("console.destroy",
                                                                         [self.cid], "result")), True)

    def create_ws(self, ws, switch=False):
        self.log("Create %s workspace.. %s" % (ws, self.rpc_call("db.add_workspace", [ws], "result")), True)
        if switch:
            self.set_ws(ws)
        return ws

    def set_ws(self, ws):
        self.log("Switch to %s workspace.. %s" % (ws, self.rpc_call("db.set_workspace", [ws], "result")), True)

    def destroy_ws(self, ws):
        self.log("Delete %s workspace.. %s" % (ws, self.rpc_call("db.del_workspace", [ws], "result")), True)

    def import_xml_data(self, ws, xml):
        content = open(xml, "r").read()
        self.log("Importing data from %s.. %s" % (xml, self.rpc_call("db.import_data", [{"workspace": ws,
                                                                                         "data": content}], "result")), True)

    def export_current_ws(self, out):
        self.log("Exporting workspace..", True)
        self.rpc_call("console.write", [self.cid, "db_export %s\r\n" % out])

        while True:
            time.sleep(5)
            res = self.rpc_call("console.read", [self.cid])
            if res.get("data"):
                self.log("%s %s" % (res.get("prompt"), res.get("data")))
            if "Finished export" in res.get("data"):
                return True

    def wait_for_jobs(self):
        while True:
            job_list = self.rpc_call("job.list", [])
            self.log("Current jobs: %s (Total: %d)" % (",".join(job_list), len(job_list)), True)
            if len(job_list) > 0:
                for j in job_list:
                    jinfo = self.rpc_call("job.info", [j])
                    self.log("%s - %s" % (jinfo.get("jid"), jinfo.get("name")), True)
            else:
                return True
            time.sleep(10)

    def run_commands(self, commands):
        self.log("Deploy following commands: \n%s" % " msf> " + "\n msf> ".join(commands), True)
        self.rpc_call("console.write", [self.cid, "\n".join(commands)])
        self.rpc_call("console.write", [self.cid, "set PROMPT commands_deployed\r\n"])

        while True:
            time.sleep(2)
            res = self.rpc_call("console.read", [self.cid])
            if res.get("data"):
                self.log("%s %s" % (res.get("prompt"), res.get("data")))
            if "commands_deployed" in res["prompt"] and not res["busy"]:
                self.rpc_call("console.write", [self.cid, "set PROMPT msfcscan\r\n"])
                break

def banner(args, cws="unknown"):
    return """   _____________________________________________________
  |  ____  ___________________________________________  |
  | | |  \/  |/  ___|  ___/  __ \                     | |
  | | | .  . |\ `--.| |_  | /  \/___  ___ __ _ _ __   | |
  | | | |\/| | `--. \  _| | |   / __|/ __/ _` | '_ \  | |
  | | | |  | |/\__/ / |   | \__/\__ \ (_| (_| | | | | | |
  | | \_|  |_/\____/\_|    \____/___/\___\__,_|_| |_| | |
  | |  _____ ______ ______ _____ ______ ______ _____  | |
  | | |_____|______|______|_____|______|______|_____| |_|
  | |
  | | Arguments:                 Current workspace: %s
  | |  > Temp workspace: %s
  | |  > Quiet mode: %s
  | |  > Command: %s
  | |  > Resource: %s
  | |  > Options: %s
  | |  > Modules: %s
  |_|  > XML import: %s
       > Log file: %s
       > Output file: %s

""" % (
    cws,
    "enabled" if not args.disable_tmp_ws else "disabled",
    "enabled" if args.quiet else "disabled",
    args.command,
    args.resource,
    "\n  | |    --> " + args.options.replace(":", "\n  | |    --> ") if args.options else None,
    "\n  | |    --> " + args.modules.replace(",", "\n  | |    --> ") if args.modules else None,
    args.xml,
    args.log,
    args.output
)


def main():
    parser = argparse.ArgumentParser(description="msfrpc cscan plugin, for automated security testing")
    parser.add_argument("-H","--msfrpc-host", help="Override MSFRPC_HOST envvar", required=False)
    parser.add_argument("-P","--msfrpc-port", help="Override MSFRPC_PORT envvar", required=False)
    parser.add_argument("-u","--msfrpc-user", help="Override MSFRPC_USER envvar", required=False)
    parser.add_argument("-p","--msfrpc-pass", help="Override MSFRPC_PASS envvar", required=False)
    parser.add_argument("-S","--msfrpc-ssl", help="Override MSFRPC_SSL envvar", required=False, action="store_true")
    parser.add_argument("-U","--msfrpc-uri", help="Override MSFRPC_URI envvar", required=False)

    parser.add_argument("-o","--output", help="Output file", required=False)
    parser.add_argument("-l","--log", help="Log file", required=False)
    parser.add_argument("-x","--xml", help="XML to import in temp workspace", required=False)
    parser.add_argument("-m","--modules", help="Modules to use", required=False)
    parser.add_argument("-r","--resource", help="Resource to execute", required=False)
    parser.add_argument("-O","--options", help="Modules options", required=False)
    parser.add_argument("-c","--command", help="Command to execute (check, run, exploit)", default="check")
    parser.add_argument("-T","--disable-tmp-ws", help="Do not create temp workspace and use current", required=False, action="store_true")
    parser.add_argument("-q","--quiet", help="Quiet mode, set -l options to have log in a file", required=False, action="store_true")

    args = parser.parse_args()
    try:
        client = Msfrpc({
            "host": args.msfrpc_host if args.msfrpc_host else os.environ.get("MSFRPC_HOST"),
            "port": args.msfrpc_port if args.msfrpc_port else os.environ.get("MSFRPC_PORT"),
            "uri": args.msfrpc_uri if args.msfrpc_uri else os.environ.get("MSFRPC_URI"),
            "ssl": args.msfrpc_ssl if args.msfrpc_ssl else os.environ.get("MSFRPC_SSL") == 'true'
        })
        client.login(args.msfrpc_user if args.msfrpc_user else os.environ.get("MSFRPC_USER"),
                     args.msfrpc_pass if args.msfrpc_pass else os.environ.get("MSFRPC_PASS"))
    except:
        print "ERROR: Cannot connect to server.."
        exit(1)

    cscan = CscanMsf(client, args.log, args.quiet)
    commands = []
    tmp_ws = None
    current_ws = cscan.rpc_call("db.current_workspace", [], "workspace")

    print banner(args, current_ws)
    cscan.create_console()

    if not args.disable_tmp_ws and os.environ.get("CS_MSF_TMP_WS") == "enabled":
        tmp_ws = "cscan_" + "".join(random.sample(string.lowercase,6))
        cscan.create_ws(tmp_ws, True)
        if args.xml:
            cscan.import_xml_data(tmp_ws, args.xml)

    if args.options:
        for option in args.options.split(":"):
            commands.append("setg " + option.replace("=", " "))
    if args.modules:
        for module in args.modules.split(","):
            commands.append("use " + module)
            commands.append("show options")
            commands.append(args.command)
    elif args.resource:
        commands.append("resource " + args.resource)

    commands.append("\r\n")
    cscan.run_commands(commands)
    cscan.wait_for_jobs()

    if os.environ.get("CS_MSF_EXPORT") == "enabled" and args.output:
        cscan.export_current_ws(args.output)

    cscan.destroy_console()

    if tmp_ws:
        cscan.set_ws(current_ws)
        cscan.destroy_ws(tmp_ws)

if __name__ == "__main__":
    main()
