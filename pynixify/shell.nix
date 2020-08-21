# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ python ? "python3" }:
let
  pkgs = import ./nixpkgs.nix { };
  pythonPkg = builtins.getAttr python pkgs;
in pkgs.mkShell {
  name = "pynixify-env";
  buildInputs = [ (pythonPkg.withPackages (ps: with ps; [ faradaysec ])) ];
}
