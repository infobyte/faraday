# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage
, fetchPypi
, flask
, lib
, python-socketio
}:

buildPythonPackage rec {
  pname =
    "flask-socketio";
  version =
    "5.3.3";

  src =
    fetchPypi {
      inherit
        version;
      pname =
        "Flask-SocketIO";
      sha256 =
        "0pgfxy2rp45bxnmf384c87mxnw26vmhqckqzq35icsdps4npciwg";
    };

  propagatedBuildInputs =
    [
      flask
      python-socketio
    ];

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib;
    { };
}
