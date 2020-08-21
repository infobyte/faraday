# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage, fetchPypi, lib }:

buildPythonPackage rec {
  pname = "anyascii";
  version = "0.1.6";

  src = fetchPypi {
    inherit pname version;
    sha256 = "112z1jlqngcqdnpb7amb1r2yvd4n0h1748jjsfsy35qx3y32ij6r";
  };

  # TODO FIXME
  doCheck = false;

  meta = with lib; {
    description = "Unicode to ASCII transliteration";
    homepage = "https://github.com/hunterwb/any-ascii";
  };
}
