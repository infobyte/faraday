# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage, factory_boy, fetchPypi, inflection, lib, pytest }:
buildPythonPackage rec {
  pname = "pytest-factoryboy";
  version = "2.0.3";

  src = fetchPypi {
    inherit pname version;
    sha256 = "06js78jshf81i2nqgf2svb8z68wh4m34hcqdvz9rj4pcvnvkzvzz";
  };

  # TODO FIXME
  doCheck = false;

  propagatedBuildInputs = [ inflection factory_boy pytest ];

  meta = {
    description = "Factory Boy support for pytest.";
    homepage = "https://github.com/pytest-dev/pytest-factoryboy";
  };
}
