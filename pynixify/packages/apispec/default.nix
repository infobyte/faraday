# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage
, fetchPypi
, lib
}:

buildPythonPackage rec {
  pname =
    "apispec";
  version =
    "4.0.0";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "12n4w5zkn4drcn8izq68vmixmqvz6abviqkdn4ip0kaax3jjh3in";
    };

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib; {
      description =
        "A pluggable API specification generator. Currently supports the OpenAPI Specification (f.k.a. the Swagger specification).";
      homepage =
        "https://github.com/marshmallow-code/apispec";
    };
}
