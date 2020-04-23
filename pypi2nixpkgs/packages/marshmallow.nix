{ buildPythonPackage, fetchPypi, lib }:
buildPythonPackage rec {
  pname = "marshmallow";
  version = "2.21.0";

  src = builtins.fetchurl {
    url =
      "https://files.pythonhosted.org/packages/12/78/9503aeb70770388002b300b349922125ae31f44b237e048e280c4773596f/marshmallow-2.21.0.tar.gz";
    sha256 = "13gjhg3bv49pv51s970lrf5pmwr0vhsicgafv017lza3h060qfg9";
  };

  # TODO FIXME
  doCheck = false;

  buildInputs = [ ];
  propagatedBuildInputs = [ ];
}
