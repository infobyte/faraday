{ buildPythonPackage, fetchPypi, flask, lib }:
buildPythonPackage rec {
  pname = "flask-classful";
  version = "0.14.2";

  src = builtins.fetchurl {
    url =
      "https://files.pythonhosted.org/packages/aa/f5/c79cb4b711a76a0fad1b464b5e77b1786c8630783226f9e90f6060e63db0/Flask-Classful-0.14.2.tar.gz";
    sha256 = "1xxzwhv09l8j8qmww2ps9cj7fm9s5n3507zk7gdic7lyyv9sn35f";
  };

  # TODO FIXME
  doCheck = false;

  buildInputs = [ ];
  propagatedBuildInputs = [ flask ];
}
