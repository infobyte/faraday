# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage
, fetchPypi
, lib
}:

buildPythonPackage rec {
  pname =
    "cvss";
  version =
    "2.6";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "103cjcimlq9qq4dw9rsywafq0n3346m506chdpxz9my1q5x0r3qy";
    };

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib; {
      description =
        "CVSS2/3 library with interactive calculator for Python 2 and Python 3";
      homepage =
        "https://github.com/RedHatProductSecurity/cvss";
    };
}
