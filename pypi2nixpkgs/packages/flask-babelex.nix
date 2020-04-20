{ Babel, buildPythonPackage, fetchPypi, flask, jinja2, lib, speaklater }:
buildPythonPackage rec {
  pname = "flask-babelex";
  version = "0.9.4";

  src = builtins.fetchurl {
    url =
      "https://files.pythonhosted.org/packages/85/e7/217fb37ccd4bd93cd0f002028fb7c5fdf6ee0063a6beb83e43cd903da46e/Flask-BabelEx-0.9.4.tar.gz";
    sha256 = "09yfr8hlwvpgvq8kp1y7qbnnl0q28hi0348bv199ssiqx779r99r";
  };

  # TODO FIXME
  doCheck = false;

  buildInputs = [ ];
  propagatedBuildInputs = [ flask Babel speaklater jinja2 ];
}
