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
    "4.4.1";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "0a8c29h93npf5svbg3w15h4wv17z5mqnyf16nlk5j680ngn66dpb";
    };

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib;
    { };
}
