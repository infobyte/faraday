with (import ./pypi2nixpkgs/nixpkgs.nix) { };
let
  version = builtins.head (builtins.match ".*'([0-9]+.[0-9]+(.[0-9]+)?)'.*"
    (builtins.readFile ./faraday/__init__.py));

  product = if builtins.pathExists ./pypi2nixpkgs_black then
    "corp"
  else if builtins.pathExists ./pypi2nixpkgs_pink then
    "pro"
  else
    "community";

in { dockerName ? "registry.gitlab.com/faradaysec/faraday", dockerTag ? version

  # If true, will ignore the contents of the last commit as source, ignoring
  # uncommited changes. Recommended to improve reproducibility
, useLastCommit ? true }: rec {

  faraday-server = python3.pkgs.faradaysec.overrideAttrs (old:
    {
      doCheck = true;
      checkPhase = "true";
      checkInputs = with python3.pkgs; [
        pylint
        factory_boy
        pytest
        pytest-factoryboy
        responses
        hypothesis
        sphinx
        pytestcov
      ];
    } // lib.optionalAttrs useLastCommit { src = builtins.fetchGit ./.; });

  dockerImage = dockerTools.buildImage {
    name = dockerName;
    tag = dockerTag;
    created = "now";
    fromImage = null;
    contents = [ python3.pkgs.faradaysec bash gnused coreutils ];
    config = {
      Cmd = [ ./scripts/docker-entrypoint.sh ];
      ExposedPorts."5985/tcp" = { };
      Volumes."/faraday-config" = { };
      Volumes."/faraday-license" = { };
      Volumes."/faraday-storage" = { };
      Env = [ "FARADAY_HOME=/home/faraday" ];
    };
    extraCommands = ''
      # Note: The current dir is the container's root file system
      mkdir -p opt usr/bin
      cp ${./scripts/docker-server.ini} server.ini
      cp ${
        ./scripts/docker-entrypoint.sh
      } .  # Not required, but useful for debug
      cp ${coreutils}/bin/env usr/bin/env
      ln -s ${python3.pkgs.faradaysec} opt/faraday
        ${
          lib.optionalString (product != "community")
          "ln -s /home/faraday/.faraday/doc faraday-license"
        }
      ln -s /home/faraday/.faraday/storage faraday-storage
      ln -s /home/faraday/.faraday/config faraday-config
    '';
  };
}
