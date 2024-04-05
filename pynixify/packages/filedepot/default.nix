# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ anyascii, buildPythonPackage, fetchPypi, lib }:

buildPythonPackage rec {
  pname = "filedepot";
  version = "0.10.0";

  src = fetchPypi {
    inherit pname version;
    sha256 = "1j5f1lp0vzwsdk2c065vnkdfhj6jpn79h50q5s6g3282kjx2vdvp";
  };

  propagatedBuildInputs = [ anyascii ];

  # TODO FIXME
  doCheck = false;

  meta = with lib; {
    description =
      "Toolkit for storing files and attachments in web applications";
    homepage = "https://github.com/amol-/depot";
  };
}
