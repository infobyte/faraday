#!/usr/bin/env bash


set -e


if [ ! -f "$FARADAY_HOME/.faraday/config/server.ini" ]; then
    if [ -z "$PGSQL_USER" ] || [ -z "$PGSQL_PASSWD" ] || [ -z "$PGSQL_HOST" ] || [ -z "$PGSQL_DBNAME" ] ; then
        echo "$(date) Missing database configuration..."
        exit 1
    fi
    CREATE_TABLES=1
    CREATE_ADMIN=1
    echo "$(date) Creating server.ini"
    mkdir -p $FARADAY_HOME/.faraday/config
    mkdir -p $FARADAY_HOME/.faraday/storage
    mkdir -p $FARADAY_HOME/.faraday/logs
    mkdir -p $FARADAY_HOME/.faraday/session
    touch $FARADAY_HOME/.faraday/logs/alembic.log
    cp /docker_server.ini $FARADAY_HOME/.faraday/config/server.ini
    CONNECTION_STRING="connection_string = postgresql+psycopg2:\/\/$PGSQL_USER:$PGSQL_PASSWD@$PGSQL_HOST\/$PGSQL_DBNAME"
    sed -i "s/connection_string = .*/$CONNECTION_STRING/"  $FARADAY_HOME/.faraday/config/server.ini
    if [ ! -z "$REDIS_SERVER" ]; then
      REDIS_STRING="redis_session_storage = $REDIS_SERVER"
      sed -i "s/#redis_session_storage = .*/$REDIS_STRING/"  $FARADAY_HOME/.faraday/config/server.ini
    fi
else
    echo "$(date) Using existing server.ini"
    CREATE_TABLES=0
    CREATE_ADMIN=0
    sleep 3
fi

if [ $CREATE_TABLES -eq 1 ]; then
    echo "Waiting for postgres on $PGSQL_HOST"
    while ! nc -z $PGSQL_HOST 5432; do
      sleep 0.5
    done
    echo "$(date) Creating tables on database $PGSQL_DBNAME..."
    faraday-manage create-tables
fi
if [ $CREATE_ADMIN -eq 1 ]; then
    if [ -z "$FARADAY_PASSWORD" ]; then
      FARADAY_PASSWORD=$(tr -dc 'A-Za-z0-9!"#$%&'\''()*+,-./:;<=>?@[\]^_{|}~' </dev/urandom |head -c 13 ; echo)
    fi
    echo "$(date) Creating superuser..."
    faraday-manage create-superuser --username faraday --password $FARADAY_PASSWORD --email "user@email.com"
    echo "Admin user created with username: faraday password: $FARADAY_PASSWORD"
fi

echo "$(date) Running migrations ..."
faraday-manage migrate

echo "$(date) Starting application..."
faraday-server
