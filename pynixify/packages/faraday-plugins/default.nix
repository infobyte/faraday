# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ beautifulsoup4, buildPythonPackage, click, colorama, dateutil, fetchPypi
, html2text, lib, lxml, markdown, packaging, pytz, requests, simplejson
, tabulate, tldextract }:

buildPythonPackage rec {
  pname = "faraday-plugins";
  version = "1.23.0";

  src = fetchPypi {
    inherit pname version;
    sha256 = "0gjc9d8yln26jbdamrhqv5w9gsr8s570chw3vznrr8pbq1j10ihv";
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
    tldextract
  ];

  # TODO FIXME
  doCheck = false;

  meta = with lib; { description = "Faraday plugins package"; };
}
