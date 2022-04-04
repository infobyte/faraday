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
    "2.3.0";

  src =
    fetchPypi {
      inherit
        version;
      pname =
        "PyJWT";
      sha256 =
        "0hgfl0cdqrzywfg5wgjxfmsbwdy7d5736311fzbxrxh6dzav925q";
    };

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib;
    { };
}
