# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage
, fetchPypi
, lib
, marshmallow
}:

buildPythonPackage rec {
  pname =
    "webargs";
  version =
    "8.0.1";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "052nard38lki662fqydlyip242n9i8w04yyh1axwz5zfa0i05kmw";
    };

  propagatedBuildInputs =
    [
      marshmallow
    ];

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib; {
      description =
        "Declarative parsing and validation of HTTP request objects, with built-in support for popular web frameworks, including Flask, Django, Bottle, Tornado, Pyramid, Falcon, and aiohttp.";
      homepage =
        "https://github.com/marshmallow-code/webargs";
    };
}
