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
    "4.3.1";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "12942bdr6rpkva8cs0c2va37dp5fa23pmpxml5ykpzpygybjc7bf";
    };

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib;
    { };
}
