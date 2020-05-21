{ buildPythonPackage, fetchPypi, flask, lib }:
buildPythonPackage rec {
  pname = "flask-login";
  version = "0.5.0";

  src = builtins.fetchurl {
    url =
      "https://files.pythonhosted.org/packages/f9/01/f6c0a3a654ca125cf9cd273314c03a8bc6a47bf861765c8c1d375e15a28d/Flask-Login-0.5.0.tar.gz";
    sha256 = "0jqb3jfm92yyz4f8n3f92f7y59p8m9j98cyc19wavkjvbgqswcvd";
  };

  # TODO FIXME
  doCheck = false;

  buildInputs = [ ];
  propagatedBuildInputs = [ flask ];
}
