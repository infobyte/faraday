# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage, fetchPypi, flask, itsdangerous, lib, simplekv, six
, werkzeug }:

buildPythonPackage rec {
  pname = "flask-kvsession-fork";
  version = "0.6.4";

  src = fetchPypi {
    inherit version;
    pname = "Flask-KVSession-fork";
    sha256 = "1ix5zsry2nrvl2vq5dix66g40ig6999q2ry2wf0w33w2rcxnm7kh";
  };

  propagatedBuildInputs = [ flask simplekv werkzeug itsdangerous six ];

  # TODO FIXME
  doCheck = false;

  meta = with lib; {
    description = "Transparent server-side session support for flask";
    homepage = "https://github.com/infobyte/flask-kvsession";
  };
}
