# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage, celery, fetchPypi, flask, lib }:

buildPythonPackage rec {
  pname = "flask-celery-helper";
  version = "1.1.0";

  src = fetchPypi {
    inherit version;
    pname = "Flask-Celery-Helper";
    sha256 = "1igqjphhjz66xpazk9xjvz7b4szix50l6xjx1vilp2c2kjc4lka5";
  };

  propagatedBuildInputs = [ flask celery ];

  # TODO FIXME
  doCheck = false;

  meta = with lib; {
    description =
      "Celery support for Flask without breaking PyCharm inspections.";
    homepage = "https://github.com/Robpol86/Flask-Celery-Helper";
  };
}
