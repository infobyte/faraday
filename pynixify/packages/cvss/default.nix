# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage, fetchPypi, lib }:

buildPythonPackage rec {
  pname = "cvss";
  version = "3.6";

  src = fetchPypi {
    inherit pname version;
    sha256 = "168sxqhkriwrln3nrknhlqlqs873qbg3f6zz8hdw1lzw9qi1h7gj";
  };

  # TODO FIXME
  doCheck = false;

  meta = with lib; {
    description =
      "CVSS2/3/4 library with interactive calculator for Python 2 and Python 3";
    homepage = "https://github.com/RedHatProductSecurity/cvss";
  };
}
