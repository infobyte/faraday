# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage, fetchPypi, lib }:

buildPythonPackage rec {
  pname = "vine";
  version = "5.1.0";

  src = fetchPypi {
    inherit pname version;
    sha256 = "1q31krwxdvwawdn1kfqmpplix31d4jhs0qng26908hawsf0yjqlb";
  };

  # TODO FIXME
  doCheck = false;

  meta = with lib; {
    description = "Python promises.";
    homepage = "https://github.com/celery/vine";
  };
}
