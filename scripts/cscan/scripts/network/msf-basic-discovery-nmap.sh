#!/bin/bash

NAME="$(date +%s)-$(basename $0)"
echo "Run msfrpc plugin.."
./plugin/msfrpc.py --output $(realpath $2$NAME.xml) \
                   --log $(realpath $3$NAME.log) \
                   --resource basic_discovery.rc \
                   --options THREADS=100:NMAP=true:NMAPOPTS="$CS_NMAP_ARGS":RHOSTS=$(sed ':a;N;$!ba;s/\n/,/g' $1)

cp $2$NAME.xml msf-workspace.xml
