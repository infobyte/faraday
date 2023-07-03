# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ attrs, automat, buildPythonPackage, constantly, fetchPypi, hyperlink
, incremental, lib, typing-extensions, zope_interface }:

buildPythonPackage rec {
  pname = "twisted";
  version = "22.4.0";

  src = fetchPypi {
    inherit version;
    pname = "Twisted";
    sha256 = "101ny6jz4llcnw4c2kbp8g4csvgishk2bpxps85ixbnzaw7rjix0";
  };

  propagatedBuildInputs = [
    zope_interface
    constantly
    incremental
    automat
    hyperlink
    attrs
    typing-extensions
  ];

  # TODO FIXME
  doCheck = false;

  meta = with lib; { };
}
