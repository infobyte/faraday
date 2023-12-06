# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage, fetchPypi, lib }:

buildPythonPackage rec {
  pname = "psycogreen";
  version = "1.0.2";

  src = fetchPypi {
    inherit pname version;
    sha256 = "038krpdic4f89pdhdf40gp3wgmxwc23h0r8jnxv2zks9i9d88af4";
  };

  # TODO FIXME
  doCheck = false;

  meta = with lib; {
    description = "psycopg2 integration with coroutine libraries";
    homepage = "https://github.com/psycopg/psycogreen/";
  };
}
