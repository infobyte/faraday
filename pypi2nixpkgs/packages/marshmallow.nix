{ buildPythonPackage, fetchPypi, lib }:
buildPythonPackage rec {
  pname = "marshmallow";
  version = "3.6.0";

  src = builtins.fetchurl {
    url =
      "https://files.pythonhosted.org/packages/8d/1c/145aa43187ddf07ac63f7ab5907591e13710f357b1a7087679832de151bc/marshmallow-3.6.0.tar.gz";
    sha256 = "1aw4bgg38rs2fl7a1814sw7g7rfws4pxqja3p1jf5p91m8rk4ry2";
  };

  # TODO FIXME
  doCheck = false;

  buildInputs = [ ];
  propagatedBuildInputs = [ ];
}
