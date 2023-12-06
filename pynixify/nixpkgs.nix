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
    python39 = super.python39.override { inherit packageOverrides; };
    python310 = super.python310.override { inherit packageOverrides; };
  };

  nixpkgs =

    builtins.fetchTarball {
      url =
        "https://github.com/infobyte/nixpkgs/archive/952075315847102402c2148ff1b2a1f373db65f5.tar.gz";
      sha256 = "14ywbx7l9xfvpg0z4rb6izr723hp4n02108k326gxxhwvl7fgd33";
    };

  packageOverrides = self: super: {
    apispec-webframeworks =
      self.callPackage ./packages/apispec-webframeworks { };

    bidict = self.callPackage ./packages/bidict { };

    bleach = self.callPackage ./packages/bleach { };

    faraday-agent-parameters-types =
      self.callPackage ./packages/faraday-agent-parameters-types { };

    faraday-plugins = self.callPackage ./packages/faraday-plugins { };

    faradaysec = self.callPackage ./packages/faradaysec { };

    filedepot = self.callPackage ./packages/filedepot { };

    filteralchemy-fork = self.callPackage ./packages/filteralchemy-fork { };

    flask = self.callPackage ./packages/flask { };

    flask-celery-helper = self.callPackage ./packages/flask-celery-helper { };

    flask-classful = self.callPackage ./packages/flask-classful { };

    flask-kvsession-fork = self.callPackage ./packages/flask-kvsession-fork { };

    flask-limiter = self.callPackage ./packages/flask-limiter { };

    flask-login = self.callPackage ./packages/flask-login { };

    flask-security-too = self.callPackage ./packages/flask-security-too { };

    flask-sqlalchemy = self.callPackage ./packages/flask-sqlalchemy { };

    flask-wtf = self.callPackage ./packages/flask-wtf { };

    marshmallow-sqlalchemy =
      self.callPackage ./packages/marshmallow-sqlalchemy { };

    psycogreen = self.callPackage ./packages/psycogreen { };

    simplekv = self.callPackage ./packages/simplekv { };

    sqlalchemy = self.callPackage ./packages/sqlalchemy { };

    werkzeug = self.callPackage ./packages/werkzeug { };

  };

in import nixpkgs (args // { overlays = [ pynixifyOverlay ] ++ overlays; })
