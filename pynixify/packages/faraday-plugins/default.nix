# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ beautifulsoup4, buildPythonPackage, click, colorama, dateutil, fetchPypi
, html2text, lib, lxml, pytz, requests, simplejson }:

buildPythonPackage rec {
  pname = "faraday-plugins";
  version = "1.3.0";

  src = fetchPypi {
    inherit pname version;
    sha256 = "10jcajizwaql39sbaa72aymnh9r9p4y6yd9sgqg5j6i919d57i37";
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
  ];

  # TODO FIXME
  doCheck = false;

  meta = with lib; { description = "Faraday plugins package"; };
}
