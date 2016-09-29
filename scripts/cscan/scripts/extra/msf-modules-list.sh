#!/bin/bash

modules_file=msf-modules.txt
if ! test -f $modules_file; then
    echo no modules file found
    exit 1
fi

while read h; do
    NAME="$(date +%s)-$(basename $0)-$h"
    echo "Run msfrpc plugin.."
    ./plugin/msfrpc.py --output $(realpath $2$NAME.xml) \
                       --log $(realpath $3$NAME.log) \
                       --modules $(sed ':a;N;$!ba;s/\n/,/g' $modules_file) \
                       --options RHOSTS=$h:RHOST=$h \
                       --command=run
done <$1
