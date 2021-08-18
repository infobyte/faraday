# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage
, fetchPypi
, lib
, setuptools_scm
}:

buildPythonPackage rec {
  pname =
    "bidict";
  version =
    "0.21.2";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "02dy0b1k7qlhn7ajyzkrvxhyhjj0hzcq6ws3zjml9hkdz5znz92g";
    };

  buildInputs =
    [
      setuptools_scm
    ];

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib; {
      description =
        "The bidirectional mapping library for Python.";
      homepage =
        "https://bidict.readthedocs.io";
    };
}
