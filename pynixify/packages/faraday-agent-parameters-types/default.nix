# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage
, fetchPypi
, lib
, marshmallow
, pytestrunner
}:

buildPythonPackage rec {
  pname =
    "faraday-agent-parameters-types";
  version =
    "0.1.1";

  src =
    fetchPypi {
      inherit
        version;
      pname =
        "faraday_agent_parameters_types";
      sha256 =
        "1m9qx0byanr7ppaqmzrvnlplr2kfag1mpng855bq9b6zjpvksfrc";
    };

  buildInputs =
    [
      pytestrunner
    ];
  propagatedBuildInputs =
    [
      marshmallow
    ];

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib; {
      description =
        ''
          The faraday agents run code remotely to ensure your domains. This info is triggered and published
              to a faraday server instance, which had set the parameters of the code. This repository sets the models to be used
              by both sides.'';
      homepage =
        "https://github.com/infobyte/faraday_agent_parameters_types";
    };
}
