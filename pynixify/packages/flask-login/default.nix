# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage, fetchPypi, flask, lib }:

buildPythonPackage rec {
  pname = "flask-login";
  version = "0.5.0";

  src = fetchPypi {
    inherit version;
    pname = "Flask-Login";
    sha256 = "0jqb3jfm92yyz4f8n3f92f7y59p8m9j98cyc19wavkjvbgqswcvd";
  };

  propagatedBuildInputs = [ flask ];

  # TODO FIXME
  doCheck = false;

  meta = with lib; {
    description = "User session management for Flask";
    homepage = "https://github.com/maxcountryman/flask-login";
  };
}
