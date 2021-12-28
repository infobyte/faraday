# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage
, fetchPypi
, lib
}:

buildPythonPackage rec {
  pname =
    "python-engineio";
  version =
    "4.3.0";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "04fviy92zf8fcpkjnfnsch1phl2sssnhrvq5zkqm67x2rzm5xlzy";
    };

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib;
    { };
}
