# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ Babel
, buildPythonPackage
, fetchPypi
, flask
, flask-babelex
, flask_login
, flask_mail
, flask_principal
, flask_wtf
, itsdangerous
, lib
, passlib
, pytestrunner
}:

buildPythonPackage rec {
  pname =
    "flask-security";
  version =
    "3.0.0";

  src =
    fetchPypi {
      inherit
        version;
      pname =
        "Flask-Security";
      sha256 =
        "0ck4ybpppka56cqv0s26h1jjq6sqvwmqfm85ylq9zy28b9gsl7fn";
    };

  buildInputs =
    [
      Babel
      pytestrunner
    ];
  propagatedBuildInputs =
    [
      flask
      flask_login
      flask_mail
      flask_principal
      flask_wtf
      flask-babelex
      itsdangerous
      passlib
    ];

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib; {
      description =
        "Simple security for Flask apps.";
      homepage =
        "https://github.com/mattupstate/flask-security";
    };
}
