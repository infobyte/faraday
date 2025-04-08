# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ amqp, buildPythonPackage, fetchPypi, lib, tzdata, vine }:

buildPythonPackage rec {
  pname = "kombu";
  version = "5.4.2";

  src = fetchPypi {
    inherit pname version;
    sha256 = "1kzj0sscsf4im3xyfcgz3rng8nnxmyp3q3jq6x5n3z6r5zfp5xgf";
  };

  propagatedBuildInputs = [ amqp vine tzdata ];

  # TODO FIXME
  doCheck = false;

  meta = with lib; {
    description = "Messaging library for Python.";
    homepage = "https://kombu.readthedocs.io";
  };
}
