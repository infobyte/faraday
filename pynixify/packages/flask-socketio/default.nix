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
    "5.3.2";

  src =
    fetchPypi {
      inherit
        version;
      pname =
        "Flask-SocketIO";
      sha256 =
        "0n0amrzvd7sib9zpzc32prrsax4cp08a2a3qn98s7k85i25xgl8i";
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
