# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage
, fetchPypi
, lib
, marshmallow
, sqlalchemy
}:

buildPythonPackage rec {
  pname =
    "marshmallow-sqlalchemy";
  version =
    "0.27.0";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "0za0zl1vyphx2pnf2zcwbjp1lzqkdi2gcf1saa668i24aqlv288m";
    };

  propagatedBuildInputs =
    [
      marshmallow
      sqlalchemy
    ];

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib; {
      description =
        "SQLAlchemy integration with the marshmallow (de)serialization library";
      homepage =
        "https://github.com/marshmallow-code/marshmallow-sqlalchemy";
    };
}
