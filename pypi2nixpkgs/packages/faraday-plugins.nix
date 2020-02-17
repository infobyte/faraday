
    { click, simplejson, requests, fetchPypi, buildPythonPackage, beautifulsoup4, lxml, lib, html2text }:
    buildPythonPackage rec {
        pname = "faraday-plugins";
        version = "1.0.2";

            src = builtins.fetchurl {
                url = "https://files.pythonhosted.org/packages/96/09/b7e77009711944000e998219121ebdcb1d2ccc0e9a8930d78d183391477f/faraday-plugins-1.0.2.tar.gz";
                sha256 = "0mxjfc0lvrlic1hvbs75rsdr6air5i332g3n6hmjk6w0hjmjkrnp";
            };
        

        # TODO FIXME
        doCheck = false;

        buildInputs = [];
        propagatedBuildInputs = [click simplejson requests lxml html2text beautifulsoup4];
    }
    