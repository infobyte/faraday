{ buildPythonPackage, fetchPypi, lib }:
buildPythonPackage rec {
  pname = "marshmallow";
  version = "3.0.0rc5";

  src = builtins.fetchurl {
    url =
      "https://files.pythonhosted.org/packages/71/78/b27626d937534d513b7de5a3210c071bc2de0721bdc72594e7d9d42beea2/marshmallow-3.0.0rc5.tar.gz";
    sha256 = "0s3hvp4kfq4h6l0rdffmnvc7sbg2m03vj01c7y3b16x65qgj8apa";
  };

  # TODO FIXME
  doCheck = false;

  buildInputs = [ ];
  propagatedBuildInputs = [ ];
}
