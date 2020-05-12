{ buildPythonPackage, fetchPypi, lib }:
buildPythonPackage rec {
  pname = "marshmallow";
  version = "3.0.0rc7";

  src = builtins.fetchurl {
    url =
      "https://files.pythonhosted.org/packages/9c/f0/05282a6745086e4918f6b364e0da83b6347c7f66a97205003223c8ab28ac/marshmallow-3.0.0rc7.tar.gz";
    sha256 = "0hdbw8xxgyavjlhilq90jl3kr6i25brph669xnr2dgcyzgqv3p7q";
  };

  # TODO FIXME
  doCheck = false;

  buildInputs = [ ];
  propagatedBuildInputs = [ ];
}
