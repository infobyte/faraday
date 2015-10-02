#!/bin/bash
###
## Faraday Penetration Test IDE
## Copyright (C) 2015  Infobyte LLC (http://www.infobytesec.com/)
## See the file 'doc/LICENSE' for the license information
###

while read h; do
    NAME="zap_$(date +%s).xml"
    echo ./plugin/zap.py --target $h --output $2$NAME
    ./plugin/zap.py --target $h --output $2$NAME
done <$1