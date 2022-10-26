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
    "5.7.2";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "15yh533a7y8mailxniana1wbl2rkw6hdmpkw1v9i6g6vv5i50fcj";
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
