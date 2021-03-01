# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage
, email_validator
, fetchPypi
, flask
, flask_login
, flask_principal
, flask_wtf
, itsdangerous
, lib
, passlib
}:

buildPythonPackage rec {
  pname =
    "flask-security-too";
  version =
    "4.0.0";

  src =
    fetchPypi {
      inherit
        version;
      pname =
        "Flask-Security-Too";
      sha256 =
        "11sd8sk9ym0n9m9h3gqwrrq03070zj0pwwkx040vzahgzrva182a";
    };

  propagatedBuildInputs =
    [
      flask
      flask_login
      flask_principal
      flask_wtf
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
