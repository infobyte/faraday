{ beautifulsoup4, buildPythonPackage, click, dateutil, fetchPypi, html2text, lib
, lxml, pytz, requests, simplejson, colorama }:
buildPythonPackage rec {
  pname = "faraday-plugins";
  version = "1.2.3";

  src = builtins.fetchurl {
    url =
      "https://files.pythonhosted.org/packages/8a/f6/eebecbde889df283531142088ddd0f31ccec13f40bf3c5132719c26de124/faraday-plugins-1.2.3.tar.gz";
    sha256 = "857f2a7328ac06235f788a3609a6e64cea72990ee09d96ca97d8c9d3e3050422";
  };

  # TODO FIXME
  doCheck = false;

  buildInputs = [ ];
  propagatedBuildInputs =
    [ click simplejson requests lxml html2text beautifulsoup4 pytz dateutil colorama ];
}
