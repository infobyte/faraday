{ apispec, buildPythonPackage, fetchPypi, lib }:
buildPythonPackage rec {
  pname = "apispec-webframeworks";
  version = "0.5.2";

  src = builtins.fetchurl {
    url =
      "https://files.pythonhosted.org/packages/bd/35/a1eb70cd9eaee7400941ca01acff9b593a12a558031f62332927970ee400/apispec-webframeworks-0.5.2.tar.gz";
    sha256 = "1wyw30402xq2a8icrsjmy9v43jyvawcjd85ccb2zicqlg4k5pcqd";
  };

  # TODO FIXME
  doCheck = false;

  buildInputs = [ ];
  propagatedBuildInputs = [ apispec ];
}
