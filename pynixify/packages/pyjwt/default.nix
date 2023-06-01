# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage
, fetchPypi
, lib
}:

buildPythonPackage rec {
  pname =
    "pyjwt";
  version =
    "2.7.0";

  src =
    fetchPypi {
      inherit
        version;
      pname =
        "PyJWT";
      sha256 =
        "0x70qffax798pbkcn3yd9kh99yzqzlss1ra98cnilp18qjis8v5x";
    };

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib;
    { };
}
