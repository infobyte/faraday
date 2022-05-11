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
    "4.3.2";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "1pbvfwiidaf6j5vj8p982zyi8fa0xd62vgi66x9hhd36hrk8sbz0";
    };

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib;
    { };
}
