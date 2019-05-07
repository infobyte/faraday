#!/usr/bin/env bash
pip install virtualenv
virtualenv -p python2 faraday_venv
source faraday_venv/bin/activate
python setup.py install
pip install --upgrade responses pytest-xdist pytest-cov
pip install --upgrade -r requirements_dev.txt
mkdir -p ~/.faraday/config
cp tests/data/server.ini ~/.faraday/config
sed -i 's/mapped_table/persist_selectable/' faraday_venv/lib/python2.7/site-packages/flask_sqlalchemy/__init__.py  # TODO remove when flask_sqlalchemy fixes the issue
