# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ blinker, buildPythonPackage, email-validator, fetchPypi, flask, flask-login
, flask-wtf, flask_principal, itsdangerous, lib, passlib }:

buildPythonPackage rec {
  pname = "flask-security-too";
  version = "4.1.6";

  src = fetchPypi {
    inherit version;
    pname = "Flask-Security-Too";
    sha256 = "1kn6xvhmpn5c3ns9cahdb6lvysfpwckna977jp4pnkrgvvjmx2an";
  };

  propagatedBuildInputs = [
    flask
    flask-login
    flask_principal
    flask-wtf
    email-validator
    itsdangerous
    passlib
    blinker
  ];

  # TODO FIXME
  doCheck = false;

  meta = with lib; {
    description = "Simple security for Flask apps.";
    homepage = "https://github.com/Flask-Middleware/flask-security";
  };
}
