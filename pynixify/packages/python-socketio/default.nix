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
    "5.5.0";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "02ygri5qaw7ynqlnimn3b0arl6r5bh6wyc0dl4gq389ap2hjx5yf";
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
