#!/bin/bash
###
## Faraday Penetration Test IDE
## Copyright (C) 2015  Infobyte LLC (http://www.infobytesec.com/)
## See the file 'doc/LICENSE' for the license information
###


while read h; do
    NAME="w3af_$(date +%s).xml"
    echo plugin/w3af.py --target $h --output $2$NAME
    ./plugin/w3af.py --target $h --output $2$NAME
done <$1
#fix zombie w3af
kill -9 $(ps aux | grep w3af_api | awk -F" " {'print $2'}) 2> /dev/null
