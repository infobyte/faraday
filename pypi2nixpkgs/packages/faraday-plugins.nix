{ beautifulsoup4, buildPythonPackage, click, dateutil, fetchPypi, html2text, lib
, lxml, pytz, requests, simplejson }:
buildPythonPackage rec {
  pname = "faraday-plugins";
  version = "1.1";

  src = builtins.fetchurl {
    url =
      "https://files.pythonhosted.org/packages/3f/63/59fdcf2f6bc0f309fcc46b8ca58990ad84ef37d1db1b78f8a04523d52369/faraday-plugins-1.1.tar.gz";
    sha256 = "0hzlymg318j78fpfrscszsfxrs21ikxy49bx91yc77b42vf73y4f";
  };

  # TODO FIXME
  doCheck = false;

  buildInputs = [ ];
  propagatedBuildInputs =
    [ click simplejson requests lxml html2text beautifulsoup4 pytz dateutil ];
}
