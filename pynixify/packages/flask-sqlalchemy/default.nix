# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage, fetchPypi, flask, lib, sqlalchemy }:

buildPythonPackage rec {
  pname = "flask-sqlalchemy";
  version = "2.5.1";

  src = fetchPypi {
    inherit version;
    pname = "Flask-SQLAlchemy";
    sha256 = "04jrx4sjrz1b20j38qk4qin975xwz30krzq59rfv3b3w7ss49nib";
  };

  propagatedBuildInputs = [ flask sqlalchemy ];

  # TODO FIXME
  doCheck = false;

  meta = with lib; {
    description = "Adds SQLAlchemy support to your Flask application.";
    homepage = "https://github.com/pallets/flask-sqlalchemy";
  };
}
