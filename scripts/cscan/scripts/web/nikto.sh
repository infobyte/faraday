#!/bin/bash
###
## Faraday Penetration Test IDE
## Copyright (C) 2015  Infobyte LLC (http://www.infobytesec.com/)
## See the file 'doc/LICENSE' for the license information
###
while read h; do
    NAME="nikto_$(date +%s).xml"
    ${CS_NIKTO:=nikto} -host $h -output $2$NAME -Format XML
done <$1