# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage
, fetchPypi
, lib
}:

buildPythonPackage rec {
  pname =
    "anyascii";
  version =
    "0.1.7";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "1xcrhmgpv8da34sg62r0yfxzyq2kwgiaardkih9z3sm96dlhgsyh";
    };

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib;
    { };
}
