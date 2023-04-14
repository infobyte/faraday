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
    "4.4.0";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "1wjcs180yj6pq9cgml5dm9ngllbcradg37nlrz1sqc6c1v3kbh5w";
    };

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib;
    { };
}
