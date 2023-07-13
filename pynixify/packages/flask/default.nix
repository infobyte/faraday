# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage, click, fetchPypi, itsdangerous, jinja2, lib, werkzeug }:

buildPythonPackage rec {
  pname = "flask";
  version = "2.1.3";

  src = fetchPypi {
    inherit version;
    pname = "Flask";
    sha256 = "1jxnsnx9d8qkm1z8vb10wrch5fbdicbbm460sv1pa1fz2x82x5qm";
  };

  propagatedBuildInputs = [ werkzeug jinja2 itsdangerous click ];

  # TODO FIXME
  doCheck = false;

  meta = with lib; { };
}
