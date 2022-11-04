# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage
, fetchPypi
, lib
}:

buildPythonPackage rec {
  pname =
    "pyotp";
  version =
    "2.7.0";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "1dbcgpf576kmrpkx3ly8jq4g5g22r9n1rra55c1xqxyzl2mrz66f";
    };

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib; {
      description =
        "Python One Time Password Library";
      homepage =
        "https://github.com/pyotp/pyotp";
    };
}
