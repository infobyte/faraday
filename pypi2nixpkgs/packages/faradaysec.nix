
    { simplejson, flask_sqlalchemy, flask-kvsession-fork, click, fetchPypi, werkzeug, flask-classful, pytestrunner, colorama, flask, tqdm, psycopg2, filedepot, pyopenssl, marshmallow, flask-restless, buildPythonPackage, sqlalchemy, distro, filteralchemy-fork, dateutil, flask_login, simplekv, service-identity, twisted, autobahn, syslog-rfc5424-formatter, marshmallow-sqlalchemy, pyasn1, webargs, flask-security, bcrypt, faraday-plugins, pillow, alembic, lib, nplusone, pgcli, requests }:
    buildPythonPackage rec {
        pname = "faradaysec";
        version = "0.1dev";

            src = lib.cleanSource ../..;
        

        # TODO FIXME
        doCheck = false;

        buildInputs = [pytestrunner];
        propagatedBuildInputs = [werkzeug autobahn alembic bcrypt colorama click flask flask_sqlalchemy flask-classful flask_login flask-security marshmallow pillow psycopg2 pgcli pyopenssl dateutil requests pyasn1 service-identity sqlalchemy tqdm twisted webargs marshmallow-sqlalchemy filteralchemy-fork filedepot nplusone flask-restless simplejson syslog-rfc5424-formatter simplekv flask-kvsession-fork distro faraday-plugins];
    }
    