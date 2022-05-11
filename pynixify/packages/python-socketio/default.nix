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
    "5.6.0";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "1yi8wh8azy6x2n283v8g9pzbg66xrv51h94hhjrvq3ahxayymwpi";
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
