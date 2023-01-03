# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage
, fetchPypi
, lib
}:

buildPythonPackage rec {
  pname =
    "bidict";
  version =
    "0.22.1";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "07fqavlf8ydxcnr2ywylyf3asbrsqqs42pd08c4ns3l6wis7y3qy";
    };

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib;
    { };
}
