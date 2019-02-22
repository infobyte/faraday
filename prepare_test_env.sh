pip install virtualenv
virtualenv -p python2 faraday_venv
source faraday_venv/bin/activate
pip install --upgrade -r requirements_server.txt
pip install --upgrade responses pytest-xdist pytest-cov
pip install --upgrade -r requirements_dev.txt
mkdir -p ~/.faraday/config
cp test_cases/data/server.ini ~/.faraday/config
sed -i 's/mapped_table/persist_selectable/' faraday_venv/lib/python2.7/site-packages/flask_sqlalchemy/__init__.py  # TODO remove when flask_sqlalchemy fixes the issue
