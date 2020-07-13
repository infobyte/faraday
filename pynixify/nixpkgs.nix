# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ overlays ? [ ], ... }@args:
let
  pypi2nixOverlay = self: super: {
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
        "https://github.com/infobyte/nixpkgs/archive/08171b150735d24a7c47673ee3d0f364fd723360.tar.gz";
      sha256 = "0hv1sjwqsz44p8mpxwyjhy3n3791302gz1iv0ms0mbs19jpvf5hh";
    };

  packageOverrides = self: super: {
    apispec-webframeworks =
      self.callPackage ./packages/apispec-webframeworks { };

    faraday-plugins = self.callPackage ./packages/faraday-plugins { };

    faradaysec = self.callPackage ./packages/faradaysec { };

    filedepot = self.callPackage ./packages/filedepot { };

    filteralchemy-fork = self.callPackage ./packages/filteralchemy-fork { };

    flask-classful = self.callPackage ./packages/flask-classful { };

    flask-kvsession-fork = self.callPackage ./packages/flask-kvsession-fork { };

    flask-login = self.callPackage ./packages/flask-login { };

    flask-restless = self.callPackage ./packages/flask-restless { };

    flask-security = self.callPackage ./packages/flask-security { };

    mimerender = self.callPackage ./packages/mimerender { };

    nplusone = self.callPackage ./packages/nplusone { };

    pytest-factoryboy = self.callPackage ./packages/pytest-factoryboy { };

    simplekv = self.callPackage ./packages/simplekv { };

    syslog-rfc5424-formatter =
      self.callPackage ./packages/syslog-rfc5424-formatter { };

    webargs = self.callPackage ./packages/webargs { };

    werkzeug = self.callPackage ./packages/werkzeug { };

  };

in import nixpkgs (args // { overlays = [ pypi2nixOverlay ] ++ overlays; })
