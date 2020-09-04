# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage, fetchPypi, lib }:

buildPythonPackage rec {
  pname = "simplekv";
  version = "0.14.1";

  src = fetchPypi {
    inherit pname version;
    sha256 = "1xnh5k7bhvi6almfsv3zj8dzxxiv66sn46fyr4hsh7klndna6lw9";
  };

  # TODO FIXME
  doCheck = false;

  meta = with lib; {
    description = "A key-value storage for binary data, support many backends.";
    homepage = "http://github.com/mbr/simplekv";
  };
}
