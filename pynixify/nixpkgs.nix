# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ overlays ? [ ], ... }@args:
let
  pynixifyOverlay = self: super: {
    python2 = super.python2.override { inherit packageOverrides; };
    python27 = super.python27.override { inherit packageOverrides; };
    python3 = super.python3.override { inherit packageOverrides; };
    python35 = super.python35.override { inherit packageOverrides; };
    python36 = super.python36.override { inherit packageOverrides; };
    python37 = super.python37.override { inherit packageOverrides; };
    python38 = super.python38.override { inherit packageOverrides; };
  };

  nixpkgs =

    builtins.fetchTarball {
      url =
        "https://github.com/infobyte/nixpkgs/archive/5b9ec00761376dc3749786d90aef2776f8962218.tar.gz";
      sha256 = "1sxh04n3aw0lh3mjaraqqhcinz3zkm7hl1i36hc5rmzijanaaq1v";
    };

  packageOverrides = self: super: {
    anyascii = self.callPackage ./packages/anyascii { };

    apispec-webframeworks =
      self.callPackage ./packages/apispec-webframeworks { };

    faraday-plugins = self.callPackage ./packages/faraday-plugins { };

    faradaysec = self.callPackage ./packages/faradaysec { };

    filedepot = self.callPackage ./packages/filedepot { };

    filteralchemy-fork = self.callPackage ./packages/filteralchemy-fork { };

    flask-classful = self.callPackage ./packages/flask-classful { };

    flask-kvsession-fork = self.callPackage ./packages/flask-kvsession-fork { };

    flask-login = self.callPackage ./packages/flask-login { };

    flask-security = self.callPackage ./packages/flask-security { };

    nplusone = self.callPackage ./packages/nplusone { };

    pytest-factoryboy = self.callPackage ./packages/pytest-factoryboy { };

    simplekv = self.callPackage ./packages/simplekv { };

    syslog-rfc5424-formatter =
      self.callPackage ./packages/syslog-rfc5424-formatter { };

    webargs = self.callPackage ./packages/webargs { };

    werkzeug = self.callPackage ./packages/werkzeug { };

  };

in import nixpkgs (args // { overlays = [ pynixifyOverlay ] ++ overlays; })
