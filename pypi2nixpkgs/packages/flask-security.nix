{ Babel, buildPythonPackage, fetchPypi, flask, flask-babelex, flask-login
, flask_mail, flask_principal, flask_wtf, itsdangerous, lib, passlib
, pytestrunner }:
buildPythonPackage rec {
  pname = "flask-security";
  version = "3.0.0";

  src = builtins.fetchurl {
    url =
      "https://files.pythonhosted.org/packages/ba/c1/16e460fec7961509b10aaf8cc986fa7a1df5dced2844f42cd46732621211/Flask-Security-3.0.0.tar.gz";
    sha256 = "0ck4ybpppka56cqv0s26h1jjq6sqvwmqfm85ylq9zy28b9gsl7fn";
  };

  # TODO FIXME
  doCheck = false;

  buildInputs = [ Babel pytestrunner ];
  propagatedBuildInputs = [
    flask
    flask-login
    flask_mail
    flask_principal
    flask_wtf
    flask-babelex
    itsdangerous
    passlib
  ];
}
