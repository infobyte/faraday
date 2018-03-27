with (import <nixpkgs> {});
let
  faraday_server = stdenv.mkDerivation {
    name = "faraday_server";
    src = builtins.filterSource cleanPycs ./.;
    buildInputs = [coreutils makeWrapper python_env.interpreter];
    builder = "${bash}/bin/bash";
    args = ["-c" ''

      source $stdenv/setup
      mkdir -p $out/{bin,src}
      cp -rv ${./.}/* $out/src/

      makeWrapper \
        ${python_env.interpreter}/bin/python \
        $out/bin/faraday-server \
        --prefix PATH : $out/src \
        --add-flags ${./.}/faraday-server.py
    ''];
  };
  python_env = (import ./requirements.nix {});
  cleanPycs = path: type: type == "directory" || builtins.match ".*\.pyc" path != null;
in
  mkShell { buildInputs = [faraday_server]; }
