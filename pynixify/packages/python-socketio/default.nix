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
    "5.3.0";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "0aqwda1dnz39zr8d1aydpm22fd32aq4ihf3cngpakwzfma2rgk1x";
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
    with lib; {
      description =
        "Socket.IO server";
      homepage =
        "http://github.com/miguelgrinberg/python-socketio/";
    };
}
