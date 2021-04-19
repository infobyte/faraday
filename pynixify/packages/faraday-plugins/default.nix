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
}:

buildPythonPackage rec {
  pname =
    "faraday-plugins";
  version =
    "1.4.5";

  src =
    fetchPypi {
      inherit
        pname
        version;
      sha256 =
        "0k4m6pz5dzy8x03wycya2n86aag42nydl67a1vak4kd09ain9vd7";
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
