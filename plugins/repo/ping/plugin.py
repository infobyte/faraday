#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from plugins import core
from model import api
import re
import os

__author__     = "Facundo de Guzmán, Esteban Guillardoy"
__copyright__  = "Copyright (c) 2013, Infobyte LLC"
__credits__    = ["Facundo de Guzmán", "Esteban Guillardoy"]
__license__    = ""
__version__    = "1.0.0"
__maintainer__ = "Francisco Amato"
__email__      = "famato@infobytesec.com"
__status__     = "Development"


class CmdPingPlugin(core.PluginBase):
    """
    This plugin handles ping command.
    Basically detects if user was able to connect to a device
    """
    def __init__(self):
        core.PluginBase.__init__(self)
        self.id              = "ping"
        self.name            = "Ping"
        self.plugin_version         = "0.0.1"
        self.version  = "1.0.0"
        self._command_regex  = re.compile(r'^(sudo ping|ping|sudo ping6|ping6).*?')
        self._completition = {
                                "":"[-LRUbdfnqrvVaAB]  [-c  count]  [-m  mark]  [-i interval] [-l preload] [-p pattern] [-s packetsize] [-t ttl] [-w deadline] [-F flowlabel] [-Iinterface] [-M hint] [-N nioption] [-Q tos] [-S sndbuf] [-T timestamp option] [-W timeout] [hop ...] destination",
                                "-a":"Audible ping.",
                                "-A":"Adaptive  ping.  Interpacket  interval adapts to round-trip time, so that effectively not more than one (or more, if preload is set) unanswered probes present in the network. Minimal interval is 200msec for not super-user.  On networks with low rtt this mode  is  essentially",
                                "-b":"Allow pinging a broadcast address.",
                                "-B":"Do not allow ping to change source address of probes.  The address is bound to one selected when ping starts.",
                                "-m":"mark",
                                "-c":"count",
                                "-d":"Set the SO_DEBUG option on the socket being used.  Essentially, this socket option is not used by Linux kernel.",
                                "-F":"flow label",
                                "-f":"Flood  ping.  For every ECHO_REQUEST sent a period ``.'' is printed, while for ever ECHO_REPLY received a backspace is printed.  This profast as they come back or one hundred times per second, whichever is more.  Only the super-user may use this option with zero interval.",
                                "-i":"interval",
                                "-I":"interface address.Set source address to specified interface address. Argument may be numeric IP address or name of  device.  When  pinging  IPv6 link-local",
                                "-l":"preload",
                                "-L":"Suppress loopback of multicast packets.  This flag only applies if the ping destination is a multicast address.",
                                "-N":"(nioption) Send ICMPv6 Node Information Queries (RFC4620), instead of Echo Request.",
                                "-n":"Numeric output only.  No attempt will be made to lookup symbolic names for host addresses.",
                                "-p":"pattern You  may  specify up to 16 ``pad'' bytes to fill out the packet you send.  This is useful for diagnosing data-dependent problems in a network.  For example, -p ff will cause the sent packet to be filled with all ones.",
                                "-D":"Print timestamp (unix time + microseconds as in gettimeofday) before each line.",
                                "-Q":"tos Set Quality of Service -related bits in ICMP datagrams.  tos can be either decimal or hex number.   Traditionally  (RFC1349),  these  have been  interpreted  as:  0  for reserved (currently being redefined as congestion control), 1-4 for Type of Service and 5-7 for Precedence enabled in the kernel.  In RFC2474, these fields has been redefined as 8-bit Differentiated Services (DS), consisting of: bits 0-1 of separate data (ECN will be used, here), and bits 2-7 of Differentiated Services Codepoint (DSCP).",
                                "-q":"Quiet output.  Nothing is displayed except the summary lines at startup time and when finished.",
                                "-R":"Record route.  Includes the RECORD_ROUTE option in the ECHO_REQUEST packet and displays the route buffer on returned packets.   Note  that",
                                "-r":"Bypass the normal routing tables and send directly to a host on an attached interface.  If the host is not on a directly-attached network,",
                                "-s":"packetsize",
                                "-S":"sndbuf",
                                "-t":"ttl Set the IP Time to Live.",
                                "-T":"Timestamp option",
                                "-M":"hint",
                                "-U":"Print full user-to-user latency (the old behaviour). Normally ping prints network round trip time, which can be different f.e. due to  DNS",
                                "-v":"Verbose output.",
                                "-V":"Show version and exit.",
                                "-w":"deadline",
                                "-W":"timeout",
                    }

    def parseOutputString(self, output, debug = False):

        reg=re.search(r"PING ([\w\.-:]+)( |)\(([\w\.:]+)\)", output)
        if re.search("0 received|unknown host",output) is None and reg is not None:
            
            ip_address = reg.group(3)
            hostname=reg.group(1)
                
            
            h_id = self.createAndAddHost(ip_address)
            if self._isIPV4(ip_address):                
                i_id = self.createAndAddInterface(h_id, ip_address, ipv4_address=ip_address, hostname_resolution=[hostname])
            else:
                i_id = self.createAndAddInterface(h_id, ip_address, ipv6_address=ip_address, hostname_resolution=[hostname])

        return True
    
    def _isIPV4(self, ip):
        if len(ip.split(".")) == 4:
            return True
        else:
            return False

    def processCommandString(self, username, current_path, command_string):
        """
        """
        return None

def createPlugin():
    return CmdPingPlugin()
