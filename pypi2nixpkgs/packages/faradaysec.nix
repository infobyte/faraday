
    { requests, pytestrunner, twisted, simplekv, lib, bcrypt, pgcli, autobahn, tqdm, flask_sqlalchemy, distro, psycopg2, apispec-webframeworks, sqlalchemy, click, flask-security, webargs, flask-restless, fetchPypi, pyopenssl, pyasn1, nplusone, apispec, flask-classful, marshmallow, syslog-rfc5424-formatter, faraday-plugins, filteralchemy-fork, flask, pillow, alembic, werkzeug, buildPythonPackage, flask-kvsession-fork, flask_login, simplejson, dateutil, filedepot, service-identity, colorama, marshmallow-sqlalchemy }:
    buildPythonPackage rec {
        pname = "faradaysec";
        version = "0.1dev";

            src = lib.cleanSource ../..;
        

        # TODO FIXME
        doCheck = false;

        buildInputs = [pytestrunner];
        propagatedBuildInputs = [werkzeug autobahn alembic bcrypt colorama click flask flask_sqlalchemy flask-classful flask_login flask-security marshmallow pillow psycopg2 pgcli pyopenssl dateutil requests pyasn1 service-identity sqlalchemy tqdm twisted webargs marshmallow-sqlalchemy filteralchemy-fork filedepot nplusone flask-restless simplejson syslog-rfc5424-formatter simplekv flask-kvsession-fork distro faraday-plugins apispec apispec-webframeworks];
    }
    