# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ bidict
, buildPythonPackage
, fetchPypi
, lib
, python-engineio
}:

buildPythonPackage rec {
  pname =
    "python-socketio";
  version =
    "5.4.1";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "1c17cvm91map3rbgl5156y6zwzz2wyqvm31298a23d7bvwyjfkpg";
    };

  propagatedBuildInputs =
    [
      bidict
      python-engineio
    ];

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib;
    { };
}
