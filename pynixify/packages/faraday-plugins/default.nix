# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ beautifulsoup4, buildPythonPackage, click, colorama, dateutil, fetchPypi
, html2text, lib, lxml, pytz, requests, simplejson }:
buildPythonPackage rec {
  pname = "faraday-plugins";
  version = "1.2.1";

  src = fetchPypi {
    inherit pname version;
    sha256 = "0mpak420k5phl0c32vcgi017r6snmm4pp3y33xzw4jivkkfji5vk";
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
