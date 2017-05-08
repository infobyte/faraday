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
		           --resource $(realpath scripts/resources/autosploit.rc) \
		           --options THREADS=100:TARGET_PLATFORM=aix,android,bsdi,dialup,firefox,freebsd,hpux,irix,linux,mainframe,multi,netware,solaris,unix,windows:BLACKLIST=freebsd/samba/trans2open,linux/samba/trans2open,osx/samba/trans2open,solaris/samba/trans2open

cp $2$NAME.xml $xml
