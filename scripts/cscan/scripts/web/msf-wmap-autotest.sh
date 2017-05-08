#!/bin/bash

xml=msf-workspace.xml
if ! test -f $xml; then
    echo XML file $xml not found
    exit 1
fi

NAME="$(date +%s)-$(basename $0)"
echo "Run msfrpc plugin.."
./plugin/msfrpc.py --output $(realpath $2$NAME.xml) \
                   --log $(realpath $3$NAME.log) \
                   --xml $xml \
                   --resource wmap_autotest.rc \
                   --options THREADS=100:WMAP_PROFILE=profile

cp $2$NAME.xml $xml
