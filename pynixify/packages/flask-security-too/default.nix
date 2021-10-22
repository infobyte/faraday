# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ blinker
, buildPythonPackage
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
    "4.1.2";

  src =
    fetchPypi {
      inherit
        version;
      pname =
        "Flask-Security-Too";
      sha256 =
        "16ws5n08vm7wsa2f7lrkxvc7jl3ah1xfylhhyzb4vvqmlk7x9hw8";
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
      blinker
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
