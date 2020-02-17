{ overlays ? [ ], ...}@args:
    let
        pypi2nixOverlay = self: super: {
            python3 = super.python3.override { inherit packageOverrides; };
        };

        
            nixpkgs =
                builtins.fetchTarball {
                    url = https://github.com/nixos/nixpkgs/archive/f1f5247103494195d00afd0b0f4ae789dedfd0e4.tar.gz;
                    sha256 = "0xnpbvz48r74xa6amzr18imyb5lfkxpgwsp56rfxn358vdrfq0wx";
                };
        

        packageOverrides = self: super: {
    

            faradaysec =
                self.callPackage ./packages/faradaysec.nix { };
        

            flask =
                self.callPackage ./packages/flask.nix { };
        

            flask-classful =
                self.callPackage ./packages/flask-classful.nix { };
        

            flask-security =
                self.callPackage ./packages/flask-security.nix { };
        

            flask-babelex =
                self.callPackage ./packages/flask-babelex.nix { };
        

            pgcli =
                self.callPackage ./packages/pgcli.nix { };
        

            webargs =
                self.callPackage ./packages/webargs.nix { };
        

            marshmallow-sqlalchemy =
                self.callPackage ./packages/marshmallow-sqlalchemy.nix { };
        

            filteralchemy-fork =
                self.callPackage ./packages/filteralchemy-fork.nix { };
        

            filedepot =
                self.callPackage ./packages/filedepot.nix { };
        

            nplusone =
                self.callPackage ./packages/nplusone.nix { };
        

            flask-restless =
                self.callPackage ./packages/flask-restless.nix { };
        

            mimerender =
                self.callPackage ./packages/mimerender.nix { };
        

            syslog-rfc5424-formatter =
                self.callPackage ./packages/syslog-rfc5424-formatter.nix { };
        

            simplekv =
                self.callPackage ./packages/simplekv.nix { };
        

            flask-kvsession-fork =
                self.callPackage ./packages/flask-kvsession-fork.nix { };
        

            faraday-plugins =
                self.callPackage ./packages/faraday-plugins.nix { };
        

            pytest-factoryboy =
                self.callPackage ./packages/pytest-factoryboy.nix { };
        

        };
    in import nixpkgs (args // { overlays = [ pypi2nixOverlay ] ++ overlays; })
    