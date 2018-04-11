with (import <nixpkgs> {});
let
  server_pkgs = callPackage ./nix/server {};
in
  {
    server = server_pkgs.server;
    python = server_pkgs.python;
  }
