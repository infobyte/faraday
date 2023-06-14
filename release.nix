with import ./pynixify/nixpkgs.nix { };
let
  version = builtins.head (builtins.match ".*'([0-9]+.[0-9]+(.[0-9]+)?)'.*"
    (builtins.readFile ./faraday/__init__.py));
in { useLastCommit ? true }: rec {

  faraday-server = python3.pkgs.faradaysec.overrideAttrs (old:
    assert !builtins.hasAttr "checkInputs" old; {
      name = "faraday-server-${version}";
      doCheck = true;
      checkPhase = "true";
    } // lib.optionalAttrs useLastCommit {
      src = builtins.fetchGit {
        url = ./.;
        rev = "HEAD";
      };
    });
}
