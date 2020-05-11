{ buildPythonPackage, click, fetchPypi, itsdangerous, jinja2, lib, werkzeug }:
buildPythonPackage rec {
  pname = "flask";
  version = "1.1.2";

  src = builtins.fetchurl {
    url =
      "https://files.pythonhosted.org/packages/4e/0b/cb02268c90e67545a0e3a37ea1ca3d45de3aca43ceb7dbf1712fb5127d5d/Flask-1.1.2.tar.gz";
    sha256 = "0q3h295izcil7lswkzfnyg3k5gq4hpmqmpl6i7s5m1n9szi1myjf";
  };

  # TODO FIXME
  doCheck = false;

  buildInputs = [ ];
  propagatedBuildInputs = [ werkzeug jinja2 itsdangerous click ];
}
