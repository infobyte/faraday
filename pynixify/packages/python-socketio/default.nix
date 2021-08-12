# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ bidict
, buildPythonPackage
, fetchPypi
, lib
, python-engineio
}:

buildPythonPackage rec {
  pname =
    "python-socketio";
  version =
    "5.4.0";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "0i15p94b592aa2h3vn3zs9qc8izv6kc4vmhjlkg9d3hn3yg7r06a";
    };

  propagatedBuildInputs =
    [
      bidict
      python-engineio
    ];

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib;
    { };
}
