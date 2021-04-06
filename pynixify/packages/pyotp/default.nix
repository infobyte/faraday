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
    "2.6.0";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "0cn4z5nv526f0l7v131piysiy9hhgbacfqd9kmmnl6qc1vadz3fj";
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
