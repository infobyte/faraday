{ alembic, apispec, apispec-webframeworks, autobahn, bcrypt, buildPythonPackage
, click, colorama, dateutil, distro, email_validator, faraday-plugins, fetchPypi
, filedepot, filteralchemy-fork, flask, flask-classful, flask-kvsession-fork
, flask-login, flask-restless, flask-security, flask_sqlalchemy, lib
, marshmallow, marshmallow-sqlalchemy, nplusone, pgcli, pillow, psycopg2, pyasn1
, pyopenssl, pytestrunner, requests, service-identity, simplejson, simplekv
, sqlalchemy, syslog-rfc5424-formatter, tqdm, twisted, webargs, werkzeug
, wtforms }:
buildPythonPackage rec {
  pname = "faradaysec";
  version = "0.1dev";

  src = lib.cleanSource ../..;

  # TODO FIXME
  doCheck = false;

  buildInputs = [ pytestrunner ];
  propagatedBuildInputs = [
    werkzeug
    autobahn
    alembic
    bcrypt
    colorama
    click
    flask
    flask_sqlalchemy
    flask-classful
    email_validator
    wtforms
    flask-login
    flask-security
    marshmallow
    pillow
    psycopg2
    pgcli
    pyopenssl
    dateutil
    requests
    pyasn1
    service-identity
    sqlalchemy
    tqdm
    twisted
    webargs
    marshmallow-sqlalchemy
    filteralchemy-fork
    filedepot
    nplusone
    flask-restless
    simplejson
    syslog-rfc5424-formatter
    simplekv
    flask-kvsession-fork
    distro
    faraday-plugins
    apispec
    apispec-webframeworks
  ];
}
