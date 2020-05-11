{ buildPythonPackage, factory_boy, fetchPypi, inflection, lib, pytest }:
buildPythonPackage rec {
  pname = "pytest-factoryboy";
  version = "2.0.3";

  src = builtins.fetchurl {
    url =
      "https://files.pythonhosted.org/packages/77/8b/ec891cea6f61ac849bd68ff677ee2176eaec606fa1b7a7a4a80fa17ce6b1/pytest-factoryboy-2.0.3.tar.gz";
    sha256 = "06js78jshf81i2nqgf2svb8z68wh4m34hcqdvz9rj4pcvnvkzvzz";
  };

  # TODO FIXME
  doCheck = false;

  buildInputs = [ ];
  propagatedBuildInputs = [ inflection factory_boy pytest ];
}
