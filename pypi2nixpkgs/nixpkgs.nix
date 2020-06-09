{ overlays ? [ ], ... }@args:
let
  pypi2nixOverlay = self: super: {
    python3 = super.python3.override { inherit packageOverrides; };
  };

  nixpkgs =

    builtins.fetchTarball {
      url =
        "https://github.com/infobyte/nixpkgs/archive/3b9c8522a0c61980f03f0e120f628755af720f3c.tar.gz";
      sha256 = "1iq1mzikhfn8sjh2a9gx8sy7z4ncf0m9n0k6w9yxzh48ygfpca16";
    };

  packageOverrides = self: super: {
    apispec-webframeworks =
      self.callPackage ./packages/apispec-webframeworks.nix { };

    faraday-plugins = self.callPackage ./packages/faraday-plugins.nix { };

    faradaysec = self.callPackage ./packages/faradaysec.nix { };

    filedepot = self.callPackage ./packages/filedepot.nix { };

    filteralchemy-fork = self.callPackage ./packages/filteralchemy-fork.nix { };

    flask-classful = self.callPackage ./packages/flask-classful.nix { };

    flask-kvsession-fork =
      self.callPackage ./packages/flask-kvsession-fork.nix { };

    flask-login = self.callPackage ./packages/flask-login.nix { };

    flask-restless = self.callPackage ./packages/flask-restless.nix { };

    flask-security = self.callPackage ./packages/flask-security.nix { };

    mimerender = self.callPackage ./packages/mimerender.nix { };

    nplusone = self.callPackage ./packages/nplusone.nix { };

    pytest-factoryboy = self.callPackage ./packages/pytest-factoryboy.nix { };

    simplekv = self.callPackage ./packages/simplekv.nix { };

    syslog-rfc5424-formatter =
      self.callPackage ./packages/syslog-rfc5424-formatter.nix { };

    webargs = self.callPackage ./packages/webargs.nix { };

    werkzeug = self.callPackage ./packages/werkzeug.nix { };

  };

in import nixpkgs (args // { overlays = [ pypi2nixOverlay ] ++ overlays; })
