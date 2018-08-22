{ pkgs ? import <nixpkgs> {}
}:
let
  python_env = (pkgs.callPackage ./requirements.nix {inherit pkgs;});
  cleanPycs = path: type: type == "directory" || builtins.match ".*\.pyc" path != null;
  src = ./../..;
in
  {
    server = pkgs.stdenv.mkDerivation {
      name = "faraday_server";
      src = builtins.filterSource cleanPycs src;
      buildInputs = with pkgs; [coreutils makeWrapper python_env.interpreter];
      builder = "${pkgs.bash}/bin/bash";
      args = ["-c" ''

        source $stdenv/setup
        mkdir -p $out/{bin,src}
        cp -rv ${src}/* $out/src/

        makeWrapper \
          ${python_env.interpreter}/bin/python \
          $out/bin/faraday-server \
          --prefix PATH : $out \
          --add-flags ${src}/faraday-server.py
      ''];
    };
    python = python_env;
  }
