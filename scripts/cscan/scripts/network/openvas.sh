#!/bin/bash
###
## Faraday Penetration Test IDE
## Copyright (C) 2015  Infobyte LLC (http://www.infobytesec.com/)
## See the file 'doc/LICENSE' for the license information
###

# -------------
# CONFIG PARAMS
# -------------
# Your Dashboard login data
USER_NAME=${CS_OPENVAS_USER:=admin}
# If you set this to None, you will be asked on startup
USER_PASSWORD=${CS_OPENVAS_PASSWORD:=openvas}

# Your targets, seperated by space
#TARGET_SRVS="localhost"
# The name of the OpenVAS preset for the scan
# The following configs are available by default:
#     Discovery
#     empty
#     Full and fast
#     Full and fast ultimate
#     Full and very deep
#     Full and very deep ultimate
#     Host Discovery
#     System Discovery
SCAN_CONFIG=${CS_OPENVAS_SCAN_CONFIG:='Full and fast'}
# A valid "alive_test" parameter
# Defines how it is determined if the targets are alive
# Currently, valid values are the following:
#     Scan Config Default
#     ICMP, TCP-ACK Service & ARP Ping
#     TCP-ACK Service & ARP Ping
#     ICMP & ARP Ping
#     ICMP & TCP-ACK Service Ping
#     ARP Ping
#     TCP-ACK Service Ping
#     TCP-SYN Service Ping
#     ICMP Ping
#     Consider Alive
ALIVE_TEST=${CS_OPENVAS_ALIVE_TEST:='ICMP, TCP-ACK Service &amp; ARP Ping'}

CS_OMP=${CS_OPENVAS:=omp}


function fail {
    echo "There was an error during execution! Current action: $1"
    exit 1
}

function sindex {
    x="${1%%$2*}"
    [[ $x = $1 ]] && echo -1 || echo ${#x}
}


THREAT=0
ADDRS=""
SRV=$1

while read h; do

echo "Processing target $h..."

#echo $CS_OMP -u $USER_NAME -w $USER_PASSWORD --xml=\
"<create_target>\
<name>TARG$(date +%s)</name><hosts>$h</hosts>\
<alive_tests>$ALIVE_TEST</alive_tests>\
</create_target>"

TARGET_RETURN=$($CS_OMP -u $USER_NAME -w $USER_PASSWORD --xml=\
"<create_target>\
<name>TARG$(date +%s)</name><hosts>$h</hosts>\
<alive_tests>$ALIVE_TEST</alive_tests>\
</create_target>")
echo "$TARGET_RETURN" | grep -m1 'resource created' || fail 'creating target'

T_ID_INDEX=$(sindex "$TARGET_RETURN" "id=")
T_ID_INDEX=$((T_ID_INDEX + 4))
T_ID=${TARGET_RETURN:T_ID_INDEX:36}
echo "> Target has ID $T_ID"

C_ID=$($CS_OMP -u $USER_NAME -w $USER_PASSWORD -g | grep -i "$TEST_CONFIG")
if [ $? -ne 0 ]; then fail 'getting configs'; fi

C_ID=${C_ID:0:36}
echo "> Config $TEST_CONFIG has ID $C_ID"

J_ID=$($CS_OMP -u $USER_NAME -w $USER_PASSWORD -C -n "CScan openvas" \
    --target="$T_ID" --config="$C_ID")
if [ $? -ne 0 ]; then fail 'creating job'; fi
echo "> Created job with ID $J_ID"

R_ID=$($CS_OMP -u $USER_NAME -w $USER_PASSWORD -S "$J_ID")
if [ $? -ne 0 ]; then fail 'starting job'; fi
echo "> Started job, report gets ID $R_ID"

while true; do
    RET=$($CS_OMP -u $USER_NAME -w $USER_PASSWORD -G)
    if [ $? -ne 0 ]; then fail 'querying jobs'; fi
    RET=$(echo "$RET" | grep -m1 "$J_ID")
    echo $RET
    echo "$RET" | grep -m1 -i "fail" && fail 'running job'
    echo "$RET" | grep -m1 -i  -E "done|Stopped" && break
    sleep 1
done

echo "> Job done, generating report..."

FILENAME=${h// /_}
FILENAME="openvas_${FILENAME//[^a-zA-Z0-9_\.\-]/}_$(date +%s)"
$CS_OMP -u $USER_NAME -w $USER_PASSWORD -R "$R_ID" > $2$FILENAME.xml
if [ $? -ne 0 ]; then fail 'getting report'; fi

echo "Scan done"

echo "Remove task"
$CS_OMP -u $USER_NAME -w $USER_PASSWORD -D "$J_ID"


done <$1
