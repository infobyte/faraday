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
    "5.3.1";

  src =
    fetchPypi {
      inherit
        version;
      pname =
        "Flask-SocketIO";
      sha256 =
        "1ycbh9y0hb7sdiiych19gsmbgphn758gbcpmsn91srs12gyd03px";
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
