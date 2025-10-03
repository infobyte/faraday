# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ beautifulsoup4, buildPythonPackage, click, colorama, dateutil, fetchPypi
, html2text, lib, lxml, markdown, packaging, pandas, pytz, requests, simplejson
, tabulate, tldextract }:

buildPythonPackage rec {
  pname = "faraday-plugins";
  version = "1.27.0";

  src = fetchPypi {
    inherit version;
    pname = "faraday_plugins";
    sha256 = "0m94mgigksb4zvbcrnr7gmxlq7c561m4hkw3zma6193mdqfh99s5";
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
    pandas
  ];

  # TODO FIXME
  doCheck = false;

  meta = with lib; { description = "Faraday plugins package"; };
}
