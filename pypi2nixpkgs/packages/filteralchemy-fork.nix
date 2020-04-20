{ buildPythonPackage, fetchPypi, lib, marshmallow-sqlalchemy, six, webargs }:
buildPythonPackage rec {
  pname = "filteralchemy-fork";
  version = "0.1.0";

  src = builtins.fetchurl {
    url =
      "https://files.pythonhosted.org/packages/ba/79/4b39ef7e32e610e789aa987a4ae1723a937cd1cbf16a0ac5865b37dd6ca3/filteralchemy-fork-0.1.0.tar.gz";
    sha256 = "1lssfgz7vlsvyl9kpcmdjndfklyb3nkxyyqwf2jwzd8zpv9cbwvs";
  };

  # TODO FIXME
  doCheck = false;

  buildInputs = [ ];
  propagatedBuildInputs = [ six webargs marshmallow-sqlalchemy ];
}
