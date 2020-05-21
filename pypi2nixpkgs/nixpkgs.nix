{ overlays ? [ ], ... }@args:
let
  pypi2nixOverlay = self: super: {
    python3 = super.python3.override { inherit packageOverrides; };
  };

  nixpkgs = builtins.fetchTarball {
    url =
      "https://github.com/infobyte/nixpkgs/archive/22540849a31190c2dfb3748490947778390e05d8.tar.gz";
    sha256 = "1p7sf67s484gdyv65rs21wx2zsir9h079qyg74w0wc7rv79gq9sk";
  };

  packageOverrides = self: super: {

    faradaysec = self.callPackage ./packages/faradaysec.nix { };

    werkzeug = self.callPackage ./packages/werkzeug.nix { };

    flask-classful = self.callPackage ./packages/flask-classful.nix { };

    flask-security = self.callPackage ./packages/flask-security.nix { };

    webargs = self.callPackage ./packages/webargs.nix { };

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
