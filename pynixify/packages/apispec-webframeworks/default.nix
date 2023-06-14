# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ apispec, buildPythonPackage, fetchPypi, lib }:

buildPythonPackage rec {
  pname = "apispec-webframeworks";
  version = "0.5.2";

  src = fetchPypi {
    inherit pname version;
    sha256 = "1wyw30402xq2a8icrsjmy9v43jyvawcjd85ccb2zicqlg4k5pcqd";
  };

  propagatedBuildInputs = [ apispec ];

  # TODO FIXME
  doCheck = false;

  meta = with lib; {
    description = "Web framework plugins for apispec.";
    homepage = "https://github.com/marshmallow-code/apispec-webframeworks";
  };
}
