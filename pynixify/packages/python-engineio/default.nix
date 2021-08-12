# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage
, fetchPypi
, lib
}:

buildPythonPackage rec {
  pname =
    "python-engineio";
  version =
    "4.2.1";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "0qps2bhis0ms8pbncsx6xwnyd6k5ffy5hbw68wjndmcfdndk446m";
    };

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib;
    { };
}
