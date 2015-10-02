#!/bin/bash
###
## Faraday Penetration Test IDE
## Copyright (C) 2015  Infobyte LLC (http://www.infobytesec.com/)
## See the file 'doc/LICENSE' for the license information
###

NAME="nmap_$(date +%s).xml"
${CS_NMAP:=nmap} -iL $1 -oX $2$NAME
