with (import <nixpkgs> {});
let
in
  mkShell {
    buildInputs = with python27Packages;
      [virtualenv pyopenssl psycopg2 pillow pygobject3
      gobjectIntrospection gtk3 gnome3.vte
      ];
    shellHook = ''
      unset SOURCE_DATE_EPOCH  # Required to make pip work

      mkvirtualenv(){
        # Reset previous virtualenv
        type -t deactivate && deactivate
        rm -rf venv

        # Build new virtualenv with system packages
        virtualenv --system-site-packages venv
        source venv/bin/activate
        pip install -r requirements_server.txt
        pip install -r requirements.txt
        pip install -r requirements_dev.txt
      }

      if [[ -d venv ]]; then
        source venv/bin/activate
      else
        echo Creating new virtualenv
        mkvirtualenv
      fi

      # Without this, the import report dialog of the client breaks
      # Taken from https://github.com/NixOS/nixpkgs/pull/26614
      export XDG_DATA_DIRS=$XDG_ICON_DIRS:$GSETTINGS_SCHEMAS_PATH\''${XDG_DATA_DIRS:+:}\$XDG_DATA_DIRS

      alias c="PS1= python faraday.py"

    '';
  }
