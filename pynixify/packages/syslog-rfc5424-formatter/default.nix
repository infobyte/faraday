# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage, fetchPypi, lib }:

buildPythonPackage rec {
  pname = "syslog-rfc5424-formatter";
  version = "1.2.2";

  src = fetchPypi {
    inherit pname version;
    sha256 = "113fc9wbsbb63clw74f7riyv37ar1131x8lc32q2cvqd523jqsns";
  };

  # TODO FIXME
  doCheck = false;

  meta = with lib; {
    description =
      "Logging formatter which produces well-formatted RFC5424 Syslog Protocol messages";
    homepage = "https://github.com/easypost/syslog-rfc5424-formatter";
  };
}
