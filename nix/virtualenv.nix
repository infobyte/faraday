{pkgs ? (import <nixpkgs> {})}:
let
  python = (pkgs.python27.buildEnv.override {
    ignoreCollisions = true;
    extraLibs = with pkgs.python27Packages;
      [virtualenv pillow pyopenssl psycopg2];
  });
  virtualenv = pkgs.stdenv.mkDerivation {
    name = "faraday-virtualenv";
    buildInputs = [python];
    requirements = [../requirements_dev.txt ../requirements_server.txt];
    unpackPhase = "true";
    pathPhase = "true";
    configurePhase = "true";
    buildPhase = ''
      ${python.env}/bin/virtualenv --system-site-packages $out
      source $out/bin/activate
      for req in $requirements do
        pip install -r $req
      done
    '';
    installPhase = "true";
  };
in
  { inherit virtualenv;
    env = python.env;
  }
