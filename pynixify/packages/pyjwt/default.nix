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
    "2.6.0";

  src =
    fetchPypi {
      inherit
        version;
      pname =
        "PyJWT";
      sha256 =
        "1z85kwr945rbzrn5wabrsmck5x8disa9wc7b3y5gci7w65z5qa39";
    };

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib;
    { };
}
