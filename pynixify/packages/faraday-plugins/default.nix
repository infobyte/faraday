# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ beautifulsoup4, buildPythonPackage, click, colorama, dateutil, fetchPypi
, html2text, lib, lxml, markdown, packaging, pytz, requests, simplejson
, tabulate }:

buildPythonPackage rec {
  pname = "faraday-plugins";
  version = "1.13.1";

  src = fetchPypi {
    inherit pname version;
    sha256 = "054sxvn10234l72fkp3ya8nvl9mg48m29dbzz0a7c7dc1c6jix7w";
  };

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
    tabulate
    packaging
    markdown
  ];

  # TODO FIXME
  doCheck = false;

  meta = with lib; { description = "Faraday plugins package"; };
}
