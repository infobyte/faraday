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
, packaging
, pytz
, requests
, simplejson
, tabulate
}:

buildPythonPackage rec {
  pname =
    "faraday-plugins";
  version =
    "1.10.0";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "08h1vgwii5idjfqwig5bd20q6c82873ynxyq0hcy6k096m6j45zd";
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
      packaging
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
