# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage, fetchPypi, flask, itsdangerous, lib, wtforms }:

buildPythonPackage rec {
  pname = "flask-wtf";
  version = "1.0.1";

  src = fetchPypi {
    inherit version;
    pname = "Flask-WTF";
    sha256 = "1jd614662r6ifh4svs8zfwm4k8bal5z3n6pq607bas8gxrpmrzil";
  };

  propagatedBuildInputs = [ flask wtforms itsdangerous ];

  # TODO FIXME
  doCheck = false;

  meta = with lib; { };
}
