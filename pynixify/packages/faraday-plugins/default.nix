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
    "1.11.0";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "1yzvhzc4rm473057dvwmc2kv6yzp9zp9hhhaj7knn0jbc7rapv2i";
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
