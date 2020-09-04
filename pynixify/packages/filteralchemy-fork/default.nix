# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage, fetchPypi, lib, marshmallow-sqlalchemy, six, webargs }:

buildPythonPackage rec {
  pname = "filteralchemy-fork";
  version = "0.1.0";

  src = fetchPypi {
    inherit pname version;
    sha256 = "1lssfgz7vlsvyl9kpcmdjndfklyb3nkxyyqwf2jwzd8zpv9cbwvs";
  };

  propagatedBuildInputs = [ six webargs marshmallow-sqlalchemy ];

  # TODO FIXME
  doCheck = false;

  meta = with lib; {
    description =
      "Declarative query builder for SQLAlchemy. This is a fork of the original project with the changes of https://github.com/jmcarp/filteralchemy/pull/2 applied";
    homepage = "https://github.com/infobyte/filteralchemy";
  };
}
