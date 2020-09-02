# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ blinker
, buildPythonPackage
, fetchPypi
, lib
, six
}:

buildPythonPackage rec {
  pname =
    "nplusone";
  version =
    "1.0.0";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "0lanbbpi5gfwjy6rlwlxw9z6nyzr5y4b4kg20jxym9qa1jhw09hp";
    };

  propagatedBuildInputs =
    [
      six
      blinker
    ];

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib; {
      description =
        "Detecting the n+1 queries problem in Python";
      homepage =
        "https://github.com/jmcarp/nplusone";
    };
}
