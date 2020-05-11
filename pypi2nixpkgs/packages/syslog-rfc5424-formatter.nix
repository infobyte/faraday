{ buildPythonPackage, fetchPypi, lib }:
buildPythonPackage rec {
  pname = "syslog-rfc5424-formatter";
  version = "1.2.2";

  src = builtins.fetchurl {
    url =
      "https://files.pythonhosted.org/packages/45/75/95ca5b9fbc31f850a2f84da8302cc0eca1420e12c7e6064dda1569d5882e/syslog-rfc5424-formatter-1.2.2.tar.gz";
    sha256 = "113fc9wbsbb63clw74f7riyv37ar1131x8lc32q2cvqd523jqsns";
  };

  # TODO FIXME
  doCheck = false;

  buildInputs = [ ];
  propagatedBuildInputs = [ ];
}
