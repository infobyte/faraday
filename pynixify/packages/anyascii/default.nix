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
    "0.3.0";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "14xmf2xz99gdmyzal7xwc997l05siipvcpqj6cxckik4zcqp9wi4";
    };

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib;
    { };
}
