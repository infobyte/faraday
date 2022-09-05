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
    "4.3.4";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "1bhrvzjaa6fm59mmjb9xmfbrgq0caqm0vd62vkfcldlwg5rb1n6q";
    };

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib;
    { };
}
