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
    "0.3.1";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "1xhibjqqn97pq90dsrqks265rr550napaz7d3v4qdqh6h9r5gpyy";
    };

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib;
    { };
}
