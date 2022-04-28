# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage
, fetchPypi
, importlib-metadata
, lib
}:

buildPythonPackage rec {
  pname =
    "click";
  version =
    "8.1.3";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "13kvp8visj5xh9d43brnda6q0kc1s40flxa5cw0p0a9hzf5dr0kn";
    };

  propagatedBuildInputs =
    [
      importlib-metadata
    ];

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib;
    { };
}
