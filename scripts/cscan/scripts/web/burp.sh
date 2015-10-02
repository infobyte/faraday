#!/bin/bash
###
## Faraday Penetration Test IDE
## Copyright (C) 2015  Infobyte LLC (http://www.infobytesec.com/)
## See the file 'doc/LICENSE' for the license information
###
CMD=${CS_BURP:=/root/tools/burpsuite_pro_v1.6.26.jar}
while read h; do
    NAME="burp_$(date +%s).xml"
    echo java -jar -Xmx1g -Djava.awt.headless=true $CMD $h XML $2$NAME
    java -jar -Xmx1g -Djava.awt.headless=true  $CMD $h XML $2$NAME
done <$1
