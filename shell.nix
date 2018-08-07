with (import <nixpkgs> {});
let
in
  mkShell {
    buildInputs = with python27Packages;
      [virtualenv pyopenssl psycopg2 pillow];
    shellHook = ''
      unset SOURCE_DATE_EPOCH  # Required to make pip work

      makeVirtualEnv(){
        rm -rf venv
        virtualenv --system-site-packages venv
        source venv/bin/activate
        pip install -r requirements_server.txt
        pip install -r requirements_dev.txt
      }

      if [[ -d venv ]]; then
        echo Creating new virtualenv
        source venv/bin/activate
      else
        makeVirtualEnv
      fi

    '';
  }
