{ buildPythonPackage, fetchPypi, lib, marshmallow, sqlalchemy }:
buildPythonPackage rec {
  pname = "marshmallow-sqlalchemy";
  version = "0.15.0";

  src = builtins.fetchurl {
    url =
      "https://files.pythonhosted.org/packages/fe/d2/de4f83721cddc2f4f9525efe916c4e87d54ca00aa678098d9d5bcdfcf966/marshmallow-sqlalchemy-0.15.0.tar.gz";
    sha256 = "1phqbbrq1xjvc7cwasy5zws4bdb050qikfp1qg8f1hqhmipkpiaz";
  };

  # TODO FIXME
  doCheck = false;

  buildInputs = [ ];
  propagatedBuildInputs = [ marshmallow sqlalchemy ];
}
