# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage
, fetchPypi
, lib
}:

buildPythonPackage rec {
  pname =
    "anyascii";
  version =
    "0.3.2";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "0c27rr3fmc1cx9mkmgx94zdf9yil0napzfkwpjw2bqjghkpk4pcx";
    };

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib;
    { };
}
