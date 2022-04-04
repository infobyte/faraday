# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage
, fetchPypi
, importlib-metadata
, lib
}:

buildPythonPackage rec {
  pname =
    "click";
  version =
    "8.1.2";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "0whs38a2i0561kwbgigs6vic9r0a1887m2v1aw3rmv6r2kz0g5s7";
    };

  propagatedBuildInputs =
    [
      importlib-metadata
    ];

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib;
    { };
}
