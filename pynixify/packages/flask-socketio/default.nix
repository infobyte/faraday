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
    "5.1.2";

  src =
    fetchPypi {
      inherit
        version;
      pname =
        "Flask-SocketIO";
      sha256 =
        "18xvkq93pprc8ngvj1jl5b8k4fpnfihziy3ninvsjqzlgs4cqfwk";
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
