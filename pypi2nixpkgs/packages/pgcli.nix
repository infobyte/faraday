{ buildPythonPackage, cli-helpers, click, configobj, fetchPypi, humanize, lib
, pgspecial, prompt_toolkit, psycopg2, pygments, setproctitle, sqlparse }:
buildPythonPackage rec {
  pname = "pgcli";
  version = "2.1.0";

  src = builtins.fetchurl {
    url =
      "https://files.pythonhosted.org/packages/ed/90/c8d33a8be3d85347a23ccd5663b8a2e82f6c79b75eb2fd9339371a9f1284/pgcli-2.1.0.tar.gz";
    sha256 = "0p60297ppljc2nyqfchzcc17ls4m5841i7gyzqags0j8fg3s749p";
  };

  # TODO FIXME
  doCheck = false;

  buildInputs = [ ];
  propagatedBuildInputs = [
    pgspecial
    click
    pygments
    prompt_toolkit
    psycopg2
    sqlparse
    configobj
    humanize
    cli-helpers
    setproctitle
  ];
}
