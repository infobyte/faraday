# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ Babel
, buildPythonPackage
, email_validator
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
, twine
, wheel
}:

buildPythonPackage rec {
  pname =
    "flask-security-too";
  version =
    "3.4.5";

  src =
    fetchPypi {
      inherit
        version;
      pname =
        "Flask-Security-Too";
      sha256 =
        "19cdad65bxs23zz5hmr41s12359ija3p2kk0mbf9jsk1swg0b7d0";
    };

  buildInputs =
    [
      Babel
      pytestrunner
      twine
      wheel
    ];
  propagatedBuildInputs =
    [
      flask
      flask_login
      flask_mail
      flask_principal
      flask_wtf
      flask-babelex
      email_validator
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
        "https://github.com/Flask-Middleware/flask-security";
    };
}
