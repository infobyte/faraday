# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ alembic, apispec, apispec-webframeworks, autobahn, bcrypt, bidict, bleach
, buildPythonPackage, click, colorama, cryptography, cvss, dateutil, distro
, email-validator, faraday-agent-parameters-types, faraday-plugins, fetchPypi
, filedepot, filteralchemy-fork, flask, flask-classful, flask-kvsession-fork
, flask-limiter, flask-login, flask-security-too, flask-socketio
, flask-sqlalchemy, flask-wtf, flask_mail, lib, marshmallow
, marshmallow-sqlalchemy, nplusone, pgcli, pillow, psycopg2, pyasn1, pyjwt
, pyopenssl, pyotp, pytest-runner, pyyaml, requests, service-identity, simplekv
, sqlalchemy, syslog-rfc5424-formatter, tqdm, twisted, webargs, werkzeug
, wtforms }:

buildPythonPackage rec {
  pname = "faradaysec";
  version = "4.4.0";

  src = lib.cleanSource ../../..;

  buildInputs = [ pytest-runner ];
  propagatedBuildInputs = [
    pyjwt
    werkzeug
    autobahn
    alembic
    bcrypt
    colorama
    click
    flask
    flask-sqlalchemy
    flask-classful
    email-validator
    flask-wtf
    wtforms
    flask-login
    flask-security-too
    bleach
    marshmallow
    pillow
    psycopg2
    pgcli
    cryptography
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
    syslog-rfc5424-formatter
    simplekv
    flask-kvsession-fork
    distro
    faraday-plugins
    apispec
    apispec-webframeworks
    pyyaml
    bidict
    flask-socketio
    pyotp
    flask-limiter
    flask_mail
    faraday-agent-parameters-types
    cvss
  ];

  # TODO FIXME
  doCheck = false;

  meta = with lib; {
    description =
      "Open Source Collaborative Penetration Test and Vulnerability Management Platform https://www.faradaysec.com";
    homepage = "https://github.com/infobyte/faraday";
  };
}
