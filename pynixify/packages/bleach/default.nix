# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage, fetchPypi, lib, packaging, six, webencodings }:

buildPythonPackage rec {
  pname = "bleach";
  version = "4.1.0";

  src = fetchPypi {
    inherit pname version;
    sha256 = "1nkibazmw1ry4cfxs9qrkkidxdf2z1hh1b20xq1ahqdsgsrxh009";
  };

  propagatedBuildInputs = [ packaging six webencodings ];

  # TODO FIXME
  doCheck = false;

  meta = with lib; {
    description = "An easy safelist-based HTML-sanitizing tool.";
    homepage = "https://github.com/mozilla/bleach";
  };
}
