# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage, fetchPypi, lib }:

buildPythonPackage rec {
  pname = "billiard";
  version = "4.2.1";

  src = fetchPypi {
    inherit pname version;
    sha256 = "0vxk9xy6fzkasvyc3irk89f6cml9k6zbgf7msg43y1rrqnq43dhj";
  };

  # TODO FIXME
  doCheck = false;

  meta = with lib; {
    description = "Python multiprocessing fork with improvements and bugfixes";
    homepage = "https://github.com/celery/billiard";
  };
}
