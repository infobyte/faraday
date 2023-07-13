# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage, fetchPypi, flask, lib }:

buildPythonPackage rec {
  pname = "flask-classful";
  version = "0.14.2";

  src = fetchPypi {
    inherit version;
    pname = "Flask-Classful";
    sha256 = "1xxzwhv09l8j8qmww2ps9cj7fm9s5n3507zk7gdic7lyyv9sn35f";
  };

  propagatedBuildInputs = [ flask ];

  # TODO FIXME
  doCheck = false;

  meta = with lib; {
    description = "Class based views for Flask";
    homepage = "https://github.com/teracyhq/flask-classful";
  };
}
