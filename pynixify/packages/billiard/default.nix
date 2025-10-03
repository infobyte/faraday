# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage, fetchPypi, lib }:

buildPythonPackage rec {
  pname = "billiard";
  version = "4.2.2";

  src = fetchPypi {
    inherit pname version;
    sha256 = "1wzcz0wc59y552fvdia17p2jv00xk0avl1ry8rc4jw9b0rx025g8";
  };

  # TODO FIXME
  doCheck = false;

  meta = with lib; {
    description = "Python multiprocessing fork with improvements and bugfixes";
    homepage = "https://github.com/celery/billiard";
  };
}
