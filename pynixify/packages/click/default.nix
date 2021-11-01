# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage
, fetchPypi
, importlib-metadata
, lib
}:

buildPythonPackage rec {
  pname =
    "click";
  version =
    "8.0.3";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "0nybbsgaff8ihfh74nhmng6qj74pfpg99njc7ivysphg0lmr63j1";
    };

  propagatedBuildInputs =
    [
      importlib-metadata
    ];

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib;
    { };
}
