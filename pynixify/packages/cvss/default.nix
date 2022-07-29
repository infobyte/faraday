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
    "2.5";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "03msz04h8wdxpr9qczdsr5r8ix709w0afil6ya64jir6zg7lixk3";
    };

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib; {
      description =
        "CVSS2/3 library with interactive calculator for Python 2 and Python 3";
      homepage =
        "https://github.com/skontar/cvss";
    };
}
