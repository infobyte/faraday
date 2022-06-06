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
    "2.4.0";

  src =
    fetchPypi {
      inherit
        version;
      pname =
        "PyJWT";
      sha256 =
        "1fmbcwfw1463wjzwbcgg3s16rad6kfb1mc5y7jbkp6v9ihh0hafl";
    };

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib;
    { };
}
