# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage, fetchPypi, lib, unidecode }:
buildPythonPackage rec {
  pname = "filedepot";
  version = "0.7.1";

  src = fetchPypi {
    inherit pname version;
    sha256 = "1rhyhr9d4ypb7qai8rgi7h2ikyiwmx7ib6xlqid1kbg0l22j1g4k";
  };

  # TODO FIXME
  doCheck = false;

  propagatedBuildInputs = [ unidecode ];

  meta = {
    description =
      "Toolkit for storing files and attachments in web applications";
    homepage = "https://github.com/amol-/depot";
  };
}
