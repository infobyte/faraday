# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage, fetchPypi, lib }:

buildPythonPackage rec {
  pname = "billiard";
  version = "4.2.4";

  src = fetchPypi {
    inherit pname version;
    sha256 = "0px8nrlv6xj2v4d63fjhhaxbqkrfwms9nab2b36h77i0f71l5xam";
  };

  # TODO FIXME
  doCheck = false;

  meta = with lib; {
    description = "Python multiprocessing fork with improvements and bugfixes";
    homepage = "https://github.com/celery/billiard";
  };
}
