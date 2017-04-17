#!/bin/bash

while read h; do
    NAME="$(date +%s)-$(basename $0)"
    HOST=$(echo $h | cut -d/ -f3 | cut -d: -f1)
    PORT=$(echo $h | cut -d/ -f3 | cut -d: -f2)
    echo "Run msfrpc plugin.."
    ./plugin/msfrpc.py --output $(realpath $2$NAME.xml) \
                       --log $(realpath $3$NAME.log) \
                       --modules auxiliary/scanner/http/dir_scanner \
                       --options RHOSTS=$HOST:RPORT=$PORT \
                       --command=run
done <$1
