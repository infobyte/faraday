
    { flask_mail, flask-babelex, itsdangerous, pytestrunner, buildPythonPackage, flask_login, Babel, flask_wtf, fetchPypi, lib, passlib, flask, flask_principal }:
    buildPythonPackage rec {
        pname = "flask-security";
        version = "3.0.0";

            src = builtins.fetchurl {
                url = "https://files.pythonhosted.org/packages/ba/c1/16e460fec7961509b10aaf8cc986fa7a1df5dced2844f42cd46732621211/Flask-Security-3.0.0.tar.gz";
                sha256 = "0ck4ybpppka56cqv0s26h1jjq6sqvwmqfm85ylq9zy28b9gsl7fn";
            };
        

        # TODO FIXME
        doCheck = false;

        buildInputs = [Babel pytestrunner];
        propagatedBuildInputs = [flask flask_login flask_mail flask_principal flask_wtf flask-babelex itsdangerous passlib];
    }
    