# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ buildPythonPackage
, fetchPypi
, lib
}:

buildPythonPackage rec {
  pname =
    "faraday-agent-parameters-types";
  version =
    "0.1.8";

  src =
    fetchPypi {
      inherit
        version;
      pname =
        "faraday_agent_parameters_types";
      sha256 =
        "0jp0z4l3kxppbwaak7bx5lfr5ih2kldyp96mbwvxjhjhr825a2ba";
    };

  # TODO FIXME
  doCheck =
    false;

  meta =
    with lib;
    { };
}
