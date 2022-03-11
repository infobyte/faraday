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
    "8.0.4";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "1nqa17zdd16fhiizziznx95ygkcxz4f3h8qfr4lb2pvw52qxfn44";
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
