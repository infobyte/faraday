{ buildPythonPackage, fetchPypi, lib, marshmallow }:
buildPythonPackage rec {
  pname = "webargs";
  version = "6.1.0";

  src = builtins.fetchurl {
    url =
      "https://files.pythonhosted.org/packages/c0/05/787ada84c00f52636327b09368ff0212861ebf44365e799126cedca20303/webargs-6.1.0.tar.gz";
    sha256 = "0gxvd1k5czch2l3jpvgbb53wbzl2drld25rs45jcfkrwbjrpzd7b";
  };

  # TODO FIXME
  doCheck = false;

  buildInputs = [ ];
  propagatedBuildInputs = [ marshmallow ];
}
