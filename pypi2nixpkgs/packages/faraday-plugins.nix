
    { requests, beautifulsoup4, click, buildPythonPackage, simplejson, html2text, fetchPypi, lib, lxml }:
    buildPythonPackage rec {
        pname = "faraday-plugins";
        version = "1.0.3";

            src = builtins.fetchurl {
                url = "https://files.pythonhosted.org/packages/d1/ac/5e2ac1f72549dceea3a76d098cc23340d916f8dceb5fc5310b6db41e6360/faraday-plugins-1.0.3.tar.gz";
                sha256 = "00gyqyqxska4mn5f70r3wsc8l9akwhmkb7xmrmh9mcacg3yzqwdh";
            };
        

        # TODO FIXME
        doCheck = false;

        buildInputs = [];
        propagatedBuildInputs = [click simplejson requests lxml html2text beautifulsoup4];
    }
    