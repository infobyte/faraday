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
    "0.2.0";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "1b6jdd9nx15py0jqjdn154m6m491517sqlk57bbyj3x4xzywadkh";
    };

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib;
    { };
}
