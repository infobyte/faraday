# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage, fetchPypi, flask, lib, limits, six }:

buildPythonPackage rec {
  pname = "flask-limiter";
  version = "1.3.1";

  src = fetchPypi {
    inherit version;
    pname = "Flask-Limiter";
    sha256 = "1ahid37wzfv2r10mj20kd1hxh21rz5wgj3bdscpm6z44999xgmh8";
  };

  propagatedBuildInputs = [ limits flask six ];

  # TODO FIXME
  doCheck = false;

  meta = with lib; {
    description = "Rate limiting for flask applications";
    homepage = "https://flask-limiter.readthedocs.org";
  };
}
