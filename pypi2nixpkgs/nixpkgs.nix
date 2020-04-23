{ overlays ? [ ], ... }@args:
let
  pypi2nixOverlay = self: super: {
    python3 = super.python3.override { inherit packageOverrides; };
  };

  nixpkgs = builtins.fetchTarball {
    url =
      "https://github.com/infobyte/nixpkgs/archive/1cd5022ecb35f81d22fd343013eea70f85c0a118.tar.gz";
    sha256 = "05hv06n3rgd82x7076bw287cv3bix79crhdivhwq75vs2sp9ildy";
  };

  packageOverrides = self: super: {

    faradaysec = self.callPackage ./packages/faradaysec.nix { };

    flask-classful = self.callPackage ./packages/flask-classful.nix { };

    flask-security = self.callPackage ./packages/flask-security.nix { };

    marshmallow = self.callPackage ./packages/marshmallow.nix { };

    webargs = self.callPackage ./packages/webargs.nix { };

    marshmallow-sqlalchemy =
      self.callPackage ./packages/marshmallow-sqlalchemy.nix { };

    filteralchemy-fork = self.callPackage ./packages/filteralchemy-fork.nix { };

    filedepot = self.callPackage ./packages/filedepot.nix { };

    nplusone = self.callPackage ./packages/nplusone.nix { };

    flask-restless = self.callPackage ./packages/flask-restless.nix { };

    mimerender = self.callPackage ./packages/mimerender.nix { };

    syslog-rfc5424-formatter =
      self.callPackage ./packages/syslog-rfc5424-formatter.nix { };

    simplekv = self.callPackage ./packages/simplekv.nix { };

    flask-kvsession-fork =
      self.callPackage ./packages/flask-kvsession-fork.nix { };

    faraday-plugins = self.callPackage ./packages/faraday-plugins.nix { };

    apispec-webframeworks =
      self.callPackage ./packages/apispec-webframeworks.nix { };

    pytest-factoryboy = self.callPackage ./packages/pytest-factoryboy.nix { };

  };
in import nixpkgs (args // { overlays = [ pypi2nixOverlay ] ++ overlays; })
