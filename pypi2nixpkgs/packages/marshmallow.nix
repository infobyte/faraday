
    { buildPythonPackage, fetchPypi, lib }:
    buildPythonPackage rec {
        pname = "marshmallow";
        version = "2.20.5";

            src = builtins.fetchurl {
                url = "https://files.pythonhosted.org/packages/da/f1/99a0fcf54d349f615d43addd3911f63d979775a11d94ffab0f33cd71099d/marshmallow-2.20.5.tar.gz";
                sha256 = "19yb2936ay2fc9aby4lyzscipf9gd9lk0zwjy7wm3b5j84pqj87f";
            };
        

        # TODO FIXME
        doCheck = false;

        buildInputs = [];
        propagatedBuildInputs = [];
    }
    