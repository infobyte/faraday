{ blinker, buildPythonPackage, fetchPypi, lib, six }:
buildPythonPackage rec {
  pname = "nplusone";
  version = "1.0.0";

  src = builtins.fetchurl {
    url =
      "https://files.pythonhosted.org/packages/26/da/663f551cdda166eaf75a564f64d022c6eb03c710ba83c3fb0f4ac664ebde/nplusone-1.0.0.tar.gz";
    sha256 = "0lanbbpi5gfwjy6rlwlxw9z6nyzr5y4b4kg20jxym9qa1jhw09hp";
  };

  # TODO FIXME
  doCheck = false;

  buildInputs = [ ];
  propagatedBuildInputs = [ six blinker ];
}
