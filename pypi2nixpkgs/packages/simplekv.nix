{ buildPythonPackage, fetchPypi, lib }:
buildPythonPackage rec {
  pname = "simplekv";
  version = "0.14.1";

  src = builtins.fetchurl {
    url =
      "https://files.pythonhosted.org/packages/30/6f/a6cafd4e87757e316468bf56287806b8df8ad4505f6da449a507e8cbacee/simplekv-0.14.1.tar.gz";
    sha256 = "1xnh5k7bhvi6almfsv3zj8dzxxiv66sn46fyr4hsh7klndna6lw9";
  };

  # TODO FIXME
  doCheck = false;

  buildInputs = [ ];
  propagatedBuildInputs = [ ];
}
