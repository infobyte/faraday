with (import <nixpkgs> {});
  mkShell {
    buildInputs = [pandoc] ++ (with python27Packages;
      [virtualenv pyopenssl psycopg2 pillow pygobject3 pynacl matplotlib lxml ldap
      gobjectIntrospection gtk3 gnome3.vte ipython gssapi
      ]);
    shellHook = ''
      unset SOURCE_DATE_EPOCH  # Required to make pip work

      VENV_PATH=.venv-white
      grep -q p- VERSION && VENV_PATH=.venv-pink
      grep -q b- VERSION && VENV_PATH=.venv-black
      grep -q c- VERSION && VENV_PATH=.venv-black

      mkvirtualenv(){
        # Reset previous virtualenv
        type -t deactivate && deactivate
        rm -rf $VENV_PATH

        # Build new virtualenv with system packages
        virtualenv --system-site-packages $VENV_PATH
        source $VENV_PATH/bin/activate
        ./develop.sh
        # pip install -r requirements_server.txt
        # pip install -r requirements.txt
        pip install -r requirements_dev.txt
      }

      if [[ -d $VENV_PATH ]]; then
        source $VENV_PATH/bin/activate
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
