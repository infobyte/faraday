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
		           --resource $(realpath scripts/resources/autoscan.rc) \
		           --options MAX_LEN=100:THREADS=100:BLACKLIST=scanner/telnet/brocade_enable_login,scanner/rogue/rogue_recv \
		           --quiet

cp $2$NAME.xml $xml
