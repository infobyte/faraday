# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage, fetchPypi, lib }:

buildPythonPackage rec {
  pname = "bidict";
  version = "0.22.0";

  src = fetchPypi {
    inherit pname version;
    sha256 = "1n2vkynb22f9pz9k0m4wnxwjla3whib5fafy2pkccz792lz6p0jw";
  };

  # TODO FIXME
  doCheck = false;

  meta = with lib; {
    description = "The bidirectional mapping library for Python.";
    homepage = "https://bidict.readthedocs.io";
  };
}
