{ buildPythonPackage, fetchPypi, lib }:
buildPythonPackage rec {
  pname = "werkzeug";
  version = "1.0.1";

  src = builtins.fetchurl {
    url =
      "https://files.pythonhosted.org/packages/10/27/a33329150147594eff0ea4c33c2036c0eadd933141055be0ff911f7f8d04/Werkzeug-1.0.1.tar.gz";
    sha256 = "0z74sa1xw5h20yin9faj0vvdbq713cgbj84klc72jr9nmpjv303c";
  };

  # TODO FIXME
  doCheck = false;

  buildInputs = [ ];
  propagatedBuildInputs = [ ];
}
