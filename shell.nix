with (import <nixpkgs> {});
let
in
  mkShell {
    buildInputs = with (import ./default.nix);
      [server python.interpreter];
  }
