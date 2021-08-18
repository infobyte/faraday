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
    "5.1.1";

  src =
    fetchPypi {
      inherit
        version;
      pname =
        "Flask-SocketIO";
      sha256 =
        "1cgn86f2p7il4aiw153099jamxjq22dhg03s34mlzs96gb6amz8y";
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
