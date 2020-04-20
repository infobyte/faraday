{ buildPythonPackage, fetchPypi, flask, itsdangerous, lib, simplekv, six
, werkzeug }:
buildPythonPackage rec {
  pname = "flask-kvsession-fork";
  version = "0.6.3";

  src = builtins.fetchurl {
    url =
      "https://files.pythonhosted.org/packages/9e/0e/c15210cae6741d1b6c663944126ed3949ca6600df5844093ca70521bb5ed/Flask-KVSession-fork-0.6.3.tar.gz";
    sha256 = "0j5ncqb2kwigs2h12vd5jwhj11ma2igw35yz9l79h2q2gg38nn8l";
  };

  # TODO FIXME
  doCheck = false;

  buildInputs = [ ];
  propagatedBuildInputs = [ flask simplekv werkzeug itsdangerous six ];
}
