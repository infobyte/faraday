#!/usr/bin/env python
###
## Faraday Penetration Test IDE
## Copyright (C) 2015  Infobyte LLC (http://www.infobytesec.com/)
## See the file 'doc/LICENSE' for the license information
###

config = {
            #Default setup
            'CS_CATEGORIES': 'network,web',
            'CS_SCRIPTS': 'nmap.sh,openvas.sh,nikto.sh,nessus.sh,w3af.sh',
            #NMAP
            'CS_NMAP' : "nmap",
            'CS_NMAP_ARGS' : "-O",
            #OPENVAS
            'CS_OPENVAS_USER' : 'admin',
            'CS_OPENVAS_PASSWORD' : 'openvas',
            'CS_OPENVAS_SCAN_CONFIG' : "Full and fast",
            'CS_OPENVAS_ALIVE_TEST' : "ICMP, TCP-ACK Service &amp; ARP Ping",
            'CS_OPENVAS' : 'omp',
            #BURP
            'CS_BURP' : '/root/tools/burpsuite_pro_v1.6.26.jar',
            #NIKTO
            'CS_NIKTO' : "nikto",
            'CS_NIKTO_ARGS' : "",
            #W3AF
            'CS_W3AF' : "/root/tools/w3af/w3af_api",
            'CS_W3AF_PROFILE' : "/root/tools/w3af/profiles/fast_scan.pw3af",
            #ZAP
            'CS_ZAP' : "/root/tools/zap/ZAP_D-2015-08-24/zap.sh",
            #NESSUS
            'CS_NESSUS_URL' : "https://127.0.0.1:8834",
            'CS_NESSUS_USER' : "nessus",
            'CS_NESSUS_PASS' : "nessus",
            'CS_NESSUS_PROFILE' : "Basic Network Scan",
            # MSFRPC
            'CS_MSF_TMP_WS' : 'enabled',
            'CS_MSF_EXPORT' : 'enabled',
        }
