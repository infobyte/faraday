# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage, fetchPypi, lib, python_mimeparse }:
buildPythonPackage rec {
  pname = "mimerender";
  version = "0.6.0";

  src = fetchPypi {
    inherit pname version;
    sha256 = "1imim78dypbl9fvrz21j8f13q8i96dx90m7f5ib3z371zrz3gwg7";
  };

  # TODO FIXME
  doCheck = false;

  propagatedBuildInputs = [ python_mimeparse ];

  meta = {
    description =
      "RESTful HTTP Content Negotiation for Flask, Bottle, web.py and webapp2 (Google App Engine)";
    homepage = "https://github.com/martinblech/mimerender";
  };
}
