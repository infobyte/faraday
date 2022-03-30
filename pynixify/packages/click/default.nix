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
    "8.1.0";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "1ljwrilh1q8ka0b1fyqxqi8pf8k343qizd4jl0x5srn7fcs22z4p";
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
