with import ./pynixify/nixpkgs.nix { };
let
  version = builtins.head (builtins.match ".*'([0-9]+.[0-9]+(.[0-9]+)?)'.*"
    (builtins.readFile ./faraday/__init__.py));

in { dockerName ? "registry.gitlab.com/faradaysec/faraday", dockerTag ? version
, systemUser ? "faraday", systemGroup ? "faraday", systemHome ? null
, port ? 5985, websocketPort ? 9000, bindAddress ? "localhost"

  # If true, will ignore the contents of the last commit as source, ignoring
  # uncommited changes. Recommended to improve reproducibility
, useLastCommit ? true }: rec {

  faraday-server = python38.pkgs.faradaysec.overrideAttrs (old:
    {
      doCheck = true;
      checkPhase = "true";
    } // lib.optionalAttrs useLastCommit {
      src = builtins.fetchGit {
        url = ./.;
        ref = "HEAD";
      };
    });

  dockerImage = dockerTools.buildImage {
    name = dockerName;
    tag = dockerTag;
    created = "now";
    fromImage = null;
    contents = [ faraday-server bash gnused coreutils ];
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
      ln -s ${faraday-server} opt/faraday
      ln -s /home/faraday/.faraday/storage faraday-storage
      ln -s /home/faraday/.faraday/config faraday-config
    '';
  };

  systemdUnit =
    let home = if isNull systemHome then "/home/${systemUser}" else systemHome;
    in writeText "faraday-server.service" ''
      [Unit]
      Description=Faraday Server
      After=network.target

      [Service]
      Type=exec
      UMask=2002
      User=${systemUser}
      Group=${systemGroup}
      Environment=FARADAY_HOME=${home}
      ExecStart=${faraday-server}/bin/faraday-server \
        --port ${builtins.toString port} \
        --websocket_port ${builtins.toString websocketPort} \
        --bind_address ${bindAddress}
      Restart=always

      [Install]
      WantedBy=multi-user.target
    '';
}
