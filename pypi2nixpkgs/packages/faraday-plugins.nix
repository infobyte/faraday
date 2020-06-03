{ beautifulsoup4, buildPythonPackage, click, colorama, dateutil, fetchPypi
, html2text, lib, lxml, pytz, requests, simplejson }:
buildPythonPackage rec {
  pname = "faraday-plugins";
  version = "1.2";

  src = builtins.fetchurl {
    url =
      "https://files.pythonhosted.org/packages/ff/c1/28c1dfc768842bf2ca69ec4b6d73066de60136ad19521404c128626601a9/faraday-plugins-1.2.tar.gz";
    sha256 = "0jdswkvlhnn1fdvj2b2mbyql00mzl71vig8nzcjkb8bd9kfy06y4";
  };

  # TODO FIXME
  doCheck = false;

  buildInputs = [ ];
  propagatedBuildInputs = [
    click
    simplejson
    requests
    lxml
    html2text
    beautifulsoup4
    pytz
    dateutil
    colorama
  ];

  meta = { description = "Faraday plugins package"; };
}
