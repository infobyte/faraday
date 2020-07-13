# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ beautifulsoup4, buildPythonPackage, click, colorama, dateutil, fetchPypi
, html2text, lib, lxml, pytz, requests, simplejson }:
buildPythonPackage rec {
  pname = "faraday-plugins";
  version = "1.2.3";

  src = fetchPypi {
    inherit pname version;
    sha256 = "08h40pix7jfqjz59d7g01scp5sjcwsk0jdlag1gj61mc51rjlzw5";
  };

  # TODO FIXME
  doCheck = false;

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
