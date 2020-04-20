{ buildPythonPackage, fetchPypi, lib }:
buildPythonPackage rec {
  pname = "simplekv";
  version = "0.13.0";

  src = builtins.fetchurl {
    url =
      "https://files.pythonhosted.org/packages/42/8e/4f96c4038d966bafbe020c36770599ce4e0f0ccbb7b93437d7742a952e03/simplekv-0.13.0.tar.gz";
    sha256 = "01iw920m8aaak3dp0y61ny7vin5yizm55h9i2vwgkv0qhvsfhlmf";
  };

  # TODO FIXME
  doCheck = false;

  buildInputs = [ ];
  propagatedBuildInputs = [ ];
}
