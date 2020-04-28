with (import ./pypi2nixpkgs/nixpkgs.nix) { };
let
  version = builtins.head (builtins.match ".*'([0-9]+.[0-9]+(.[0-9]+)?)'.*"
    (builtins.readFile ./faraday/__init__.py));
in { dockerName ? "registry.gitlab.com/faradaysec/faraday", dockerTag ? version
}: {
  dockerImage = dockerTools.buildImage {
    name = "registry.gitlab.com/faradaysec/faraday";
    tag = version;
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
      ln -s /home/faraday/.faraday/doc faraday-license  # Not useful in Community version
      ln -s /home/faraday/.faraday/storage faraday-storage
      ln -s /home/faraday/.faraday/config faraday-config
    '';
  };
}
