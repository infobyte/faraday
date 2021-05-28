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
    "0.25.0";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "0i39ckrixh1w9fmkm0wl868gvza72j5la0x6dd0cij9shf1iyjgi";
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
