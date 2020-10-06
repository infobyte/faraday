# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage
, fetchPypi
, lib
}:

buildPythonPackage rec {
  pname =
    "werkzeug";
  version =
    "1.0.1";

  src =
    fetchPypi {
      inherit
        version;
      pname =
        "Werkzeug";
      sha256 =
        "0z74sa1xw5h20yin9faj0vvdbq713cgbj84klc72jr9nmpjv303c";
    };

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib; {
      description =
        "The comprehensive WSGI web application library.";
      homepage =
        "https://palletsprojects.com/p/werkzeug/";
    };
}
