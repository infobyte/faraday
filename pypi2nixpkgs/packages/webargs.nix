{ buildPythonPackage, fetchPypi, lib, marshmallow }:
buildPythonPackage rec {
  pname = "webargs";
  version = "5.5.3";

  src = builtins.fetchurl {
    url =
      "https://files.pythonhosted.org/packages/5a/46/72d3c7e0acbdb9c79caf7e03835cd7f77163026811855b59a1eaf6c0c2e5/webargs-5.5.3.tar.gz";
    sha256 = "16pjzc265yx579ijz5scffyfd1vsmi87fdcgnzaj2by6w2i445l7";
  };

  # TODO FIXME
  doCheck = false;

  buildInputs = [ ];
  propagatedBuildInputs = [ marshmallow ];

  meta = {
    description =
      "Declarative parsing and validation of HTTP request objects, with built-in support for popular web frameworks, including Flask, Django, Bottle, Tornado, Pyramid, webapp2, Falcon, and aiohttp.";
    homepage = "https://github.com/marshmallow-code/webargs";
  };
}
