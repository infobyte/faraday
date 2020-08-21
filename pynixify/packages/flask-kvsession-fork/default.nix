# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage, fetchPypi, flask, itsdangerous, lib, simplekv, six
, werkzeug }:

buildPythonPackage rec {
  pname = "flask-kvsession-fork";
  version = "0.6.3";

  src = fetchPypi {
    inherit version;
    pname = "Flask-KVSession-fork";
    sha256 = "0j5ncqb2kwigs2h12vd5jwhj11ma2igw35yz9l79h2q2gg38nn8l";
  };

  propagatedBuildInputs = [ flask simplekv werkzeug itsdangerous six ];

  # TODO FIXME
  doCheck = false;

  meta = with lib; {
    description = "Transparent server-side session support for flask";
    homepage = "https://github.com/mbr/flask-kvsession";
  };
}
