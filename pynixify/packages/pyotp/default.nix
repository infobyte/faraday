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
    "2.8.0";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "0nlcm54zqild41pbmg5smlar2sqi12mk2qyyyz0qwbd9kmyy3xf2";
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
