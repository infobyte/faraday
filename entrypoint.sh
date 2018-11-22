#!/bin/bash

echo -e '\n[+] Starting postgresql'
/etc/init.d/postgresql start

echo -e '\n[+] Initializing database'
python manage.py initdb
sed -i 's/bind_address = localhost/bind_address = 0.0.0.0/' \
  ~/.faraday/config/server.ini

echo -e '\n[+] Starting faraday'
python /root/faraday-dev/faraday-server.py
