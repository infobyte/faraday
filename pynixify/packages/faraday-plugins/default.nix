# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ beautifulsoup4
, buildPythonPackage
, click
, colorama
, dateutil
, fetchPypi
, html2text
, lib
, lxml
, pytz
, requests
, simplejson
, tabulate
}:

buildPythonPackage rec {
  pname =
    "faraday-plugins";
  version =
    "1.5.5";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "1dw7j8zfa8j9m0qcpyzl6k0z29k3j5i90lyfg2zapwkpalkgx0d1";
    };

  propagatedBuildInputs =
    [
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
    ];

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib; {
      description =
        "Faraday plugins package";
    };
}
