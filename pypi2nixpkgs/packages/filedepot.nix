{ buildPythonPackage, fetchPypi, lib, unidecode }:
buildPythonPackage rec {
  pname = "filedepot";
  version = "0.7.1";

  src = builtins.fetchurl {
    url =
      "https://files.pythonhosted.org/packages/56/40/8755419cb2cd1be41690a5c15694c738c67ea84a84ad9128222c7a4477c1/filedepot-0.7.1.tar.gz";
    sha256 = "1rhyhr9d4ypb7qai8rgi7h2ikyiwmx7ib6xlqid1kbg0l22j1g4k";
  };

  # TODO FIXME
  doCheck = false;

  buildInputs = [ ];
  propagatedBuildInputs = [ unidecode ];
}
