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
    "4.2.0";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "0xr0sq02r7y807zkkh63hd9h05frziyc8vdvymc3i4i3khcc35sf";
    };

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib; {
      description =
        "Engine.IO server";
      homepage =
        "http://github.com/miguelgrinberg/python-engineio/";
    };
}
