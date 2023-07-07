# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage, fetchPypi, lib }:

buildPythonPackage rec {
  pname = "sqlalchemy";
  version = "1.3.24";

  src = fetchPypi {
    inherit version;
    pname = "SQLAlchemy";
    sha256 = "06bmxzssc66cblk1hamskyv5q3xf1nh1py3vi6dka4lkpxy7gfzb";
  };

  # TODO FIXME
  doCheck = false;

  meta = with lib; {
    description = "Database Abstraction Library";
    homepage = "http://www.sqlalchemy.org";
  };
}
