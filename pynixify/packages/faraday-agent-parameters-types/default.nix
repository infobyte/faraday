# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage, fetchPypi, lib, marshmallow, packaging, pytest-runner
, validators }:

buildPythonPackage rec {
  pname = "faraday-agent-parameters-types";
  version = "1.9.1";

  src = fetchPypi {
    inherit version;
    pname = "faraday_agent_parameters_types";
    sha256 = "15sc33b79kn16sx8v8bq618fr679zv7s0ishic08h667wz1bhqrx";
  };

  buildInputs = [ pytest-runner ];
  propagatedBuildInputs = [ marshmallow packaging validators ];

  # TODO FIXME
  doCheck = false;

  meta = with lib; {
    description = ''
      The faraday agents run code remotely to ensure your domains. This info is triggered and published
          to a faraday server instance, which had set the parameters of the code. This repository sets the models to be used
          by both sides.'';
    homepage = "https://github.com/infobyte/faraday_agent_parameters_types";
  };
}
