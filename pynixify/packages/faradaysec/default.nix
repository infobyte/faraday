# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ alembic
, apispec
, apispec-webframeworks
, autobahn
, bcrypt
, buildPythonPackage
, click
, colorama
, dateutil
, distro
, email_validator
, factory_boy
, faraday-plugins
, fetchPypi
, filedepot
, filteralchemy-fork
, flask
, flask-classful
, flask-kvsession-fork
, flask-security
, flask_login
, flask_sqlalchemy
, hypothesis
, lib
, marshmallow
, marshmallow-sqlalchemy
, nplusone
, pgcli
, pillow
, psycopg2
, pyasn1
, pylint
, pyopenssl
, pyotp
, pytest
, pytest-factoryboy
, pytestcov
, pytestrunner
, pyyaml
, requests
, responses
, service-identity
, simplekv
, sphinx
, sqlalchemy
, syslog-rfc5424-formatter
, tqdm
, twine
, twisted
, webargs
, werkzeug
, wtforms
}:

buildPythonPackage rec {
  pname =
    "faradaysec";
  version =
    "3.14.0";

  src =
    lib.cleanSource
    ../../..;

  buildInputs =
    [
      pytestrunner
    ];
  propagatedBuildInputs =
    [
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
      flask_login
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
      syslog-rfc5424-formatter
      simplekv
      flask-kvsession-fork
      distro
      faraday-plugins
      apispec
      apispec-webframeworks
      pyyaml
      pyotp
    ];
  checkInputs =
    [
      flask
      factory_boy
      pylint
      pytest
      pytestcov
      pytest-factoryboy
      responses
      hypothesis
      sphinx
      twine
    ];

  checkPhase =
    "true  # TODO fill with the real command for testing";

  meta =
    with lib; {
      description =
        "Collaborative Penetration Test and Vulnerability Management Platform https://www.faradaysec.com";
      homepage =
        "https://github.com/infobyte/faraday";
    };
}
