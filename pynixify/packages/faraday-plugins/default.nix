# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ beautifulsoup4, buildPythonPackage, click, colorama, dateutil, fetchPypi
, html2text, lib, lxml, markdown, packaging, pytz, requests, simplejson
, tabulate, tldextract }:

buildPythonPackage rec {
  pname = "faraday-plugins";
  version = "1.24.0";

  src = fetchPypi {
    inherit version;
    pname = "faraday_plugins";
    sha256 = "0mxy949g1763vh8090dmn8z8mdx8vp505x4vnfkzqhqr8c6yqpn5";
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
