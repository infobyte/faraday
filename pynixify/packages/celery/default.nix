# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ billiard, buildPythonPackage, click, click-didyoumean, click-plugins
, click-repl, dateutil, fetchPypi, kombu, lib, tzdata, vine }:

buildPythonPackage rec {
  pname = "celery";
  version = "5.4.0";

  src = fetchPypi {
    inherit pname version;
    sha256 = "01p7lyydhqk7fna5zn49qxj3yk0xah63725dmkajjc4d1qa1jjjh";
  };

  propagatedBuildInputs = [
    billiard
    kombu
    vine
    click
    click-didyoumean
    click-repl
    click-plugins
    tzdata
    dateutil
  ];

  # TODO FIXME
  doCheck = false;

  meta = with lib; {
    description = "Distributed Task Queue.";
    homepage = "https://docs.celeryq.dev/";
  };
}
