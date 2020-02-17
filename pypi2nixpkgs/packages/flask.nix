
    { itsdangerous, jinja2, click, fetchPypi, werkzeug, lib, buildPythonPackage }:
    buildPythonPackage rec {
        pname = "flask";
        version = "1.1.1";

            src = builtins.fetchurl {
                url = "https://files.pythonhosted.org/packages/2e/80/3726a729de758513fd3dbc64e93098eb009c49305a97c6751de55b20b694/Flask-1.1.1.tar.gz";
                sha256 = "0ljdjgyjn7vh8ic1n1dc2l1cl421i6pr3kx5sz2w5irhyfbg3y8k";
            };
        

        # TODO FIXME
        doCheck = false;

        buildInputs = [];
        propagatedBuildInputs = [werkzeug jinja2 itsdangerous click];
    }
    