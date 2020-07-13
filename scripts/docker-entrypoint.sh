#!/usr/bin/env bash
#

set -e

if [ -e $PGSQL_PASSWD ];then
	PGSQL_PASSWD=`cat $PGSQL_PASSWD`
fi

if [ -z "$PGSQL_USER" ]; then
	PGSQL_USER="faraday_postgresql"
fi

if [ -z "$PGSQL_PASSWD" ]; then
	#cat is for cases when faraday runs as a docker service
	PGSQL_PASSWD=`cat $PGSQL_PASSWD`
fi

if [ -z "$PGSQL_HOST" ]; then
	PGSQL_HOST="localhost"
fi

if [ -z "$PGSQL_PGSQL_DBNAME" ]; then
	PGSQL_DBNAME="faraday"
fi

if [ -z "$LISTEN_ADDR" ]; then
	LISTEN_ADDR="127.0.0.1"
fi

echo "Restoring config file"
if [ ! -f "/home/faraday/.faraday/config/server.ini" ]; then
    mv /server.ini /home/faraday/.faraday/config/.
    CONNECTION_STRING="connection_string = postgresql+psycopg2:\/\/$PGSQL_USER:$PGSQL_PASSWD@$PGSQL_HOST\/$PGSQL_DBNAME"
    sed -i "s/connection_string = .*/$CONNECTION_STRING/"  /home/faraday/.faraday/config/server.ini
fi

export FARADAY_HOME=/home/faraday
echo "Trying to connect to database ..."
faraday-manage create-tables
faraday-manage migrate

export FARADAY_HOME=/home/faraday
/opt/faraday/bin/faraday-server
