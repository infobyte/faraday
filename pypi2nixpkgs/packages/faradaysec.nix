
    { flask_login, colorama, flask, flask-restless, tqdm, lib, webargs, psycopg2, pytestrunner, marshmallow, pgcli, faraday-plugins, filedepot, werkzeug, service-identity, flask_sqlalchemy, filteralchemy-fork, pillow, pyopenssl, simplejson, fetchPypi, nplusone, distro, twisted, autobahn, pyasn1, marshmallow-sqlalchemy, bcrypt, click, flask-classful, flask-kvsession-fork, alembic, dateutil, buildPythonPackage, flask-security, requests, syslog-rfc5424-formatter, sqlalchemy, simplekv }:
    buildPythonPackage rec {
        pname = "faradaysec";
        version = "0.1dev";

            src = lib.cleanSource ../..;
        

        # TODO FIXME
        doCheck = false;

        buildInputs = [pytestrunner];
        propagatedBuildInputs = [werkzeug autobahn alembic bcrypt colorama click flask flask_sqlalchemy flask-classful flask_login flask-security marshmallow pillow psycopg2 pgcli pyopenssl dateutil requests pyasn1 service-identity sqlalchemy tqdm twisted webargs marshmallow-sqlalchemy filteralchemy-fork filedepot nplusone flask-restless simplejson syslog-rfc5424-formatter simplekv flask-kvsession-fork distro faraday-plugins];
    }
    