{ buildPythonPackage, dateutil, fetchPypi, flask, lib, mimerender, sqlalchemy }:
buildPythonPackage rec {
  pname = "flask-restless";
  version = "0.17.0";

  src = builtins.fetchurl {
    url =
      "https://files.pythonhosted.org/packages/ae/ad/14eee74ef110f2bd8641de98675037f037dd06d614f7c435671be66a55c7/Flask-Restless-0.17.0.tar.gz";
    sha256 = "1dn2g3qkgvbbs4165hng82gkplm1bnxf010qkaf26ixx1bl7zr0x";
  };

  # TODO FIXME
  doCheck = false;

  buildInputs = [ ];
  propagatedBuildInputs = [ flask sqlalchemy dateutil mimerender ];
}
