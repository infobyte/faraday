# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage, dateutil, fetchPypi, flask, lib, mimerender, sqlalchemy }:
buildPythonPackage rec {
  pname = "flask-restless";
  version = "0.17.0";

  src = fetchPypi {
    inherit version;
    pname = "Flask-Restless";
    sha256 = "1dn2g3qkgvbbs4165hng82gkplm1bnxf010qkaf26ixx1bl7zr0x";
  };

  # TODO FIXME
  doCheck = false;

  propagatedBuildInputs = [ flask sqlalchemy dateutil mimerender ];

  meta = {
    description = "A Flask extension for easy ReSTful API generation";
    homepage = "http://github.com/jfinkels/flask-restless";
  };
}
