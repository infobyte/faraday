# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ alembic, apispec, apispec-webframeworks, autobahn, bcrypt, bidict, bleach
, buildPythonPackage, celery, click, colorama, croniter, cryptography, cvss
, dateutil, distro, elasticsearch, email-validator, factory_boy
, faraday-agent-parameters-types, faraday-plugins, fetchPypi, filedepot
, filteralchemy-fork, flask, flask-celery-helper, flask-classful
, flask-kvsession-fork, flask-limiter, flask-login, flask-security-too
, flask-socketio, flask-sqlalchemy, flask-wtf, flask_mail, gevent
, gevent-websocket, hypothesis, kombu, lib, marshmallow, marshmallow-sqlalchemy
, nplusone, pgcli, pillow, psycogreen, psycopg2, pyasn1, pyjwt, pylint
, pyopenssl, pyotp, pytest, pytest-cov, pytest-factoryboy, pytest-runner, pyyaml
, redis, requests, responses, service-identity, sh, simplekv, sphinx, sqlalchemy
, syslog-rfc5424-formatter, tqdm, twine, validators, webargs, werkzeug, wtforms
}:

buildPythonPackage rec {
  pname = "faradaysec";
  version = "5.13.0";

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
    validators
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
    celery
    kombu
    gevent
    psycogreen
    flask-celery-helper
    redis
    gevent-websocket
    sh
    elasticsearch
    croniter
  ];
  nativeBuildInputs = [
    factory_boy
    pylint
    pytest
    pytest-cov
    pytest-factoryboy
    responses
    hypothesis
    sphinx
    twine
  ];

  checkPhase = "true  # TODO fill with the real command for testing";

  meta = with lib; {
    description =
      "Open Source Collaborative Penetration Test and Vulnerability Management Platform https://www.faradaysec.com";
    homepage = "https://github.com/infobyte/faraday";
  };
}
