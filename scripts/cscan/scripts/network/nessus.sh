#!/bin/bash
###
## Faraday Penetration Test IDE
## Copyright (C) 2015  Infobyte LLC (http://www.infobytesec.com/)
## See the file 'doc/LICENSE' for the license information
###

while read h; do
    NAME="nessus_$(date +%s).xml"
    echo plugin/nessus.py --target $h --output $2$NAME
    ./plugin/nessus.py --target $h --output $2$NAME
done <$1
