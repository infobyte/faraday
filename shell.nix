with (import <nixpkgs> {});
  mkShell {
    buildInputs = [pandoc] ++ (with python3Packages;
      [virtualenv pyopenssl psycopg2 pillow pygobject3 pynacl matplotlib lxml ldap autobahn
      gobjectIntrospection gtk3 gnome3.vte gssapi pykerberos
      ]);
    shellHook = ''
      unset SOURCE_DATE_EPOCH  # Required to make pip work

      VENV_PATH=.venv-white
      [[ -f faraday/server/api/modules/reports.py ]] && VENV_PATH=.venv-pink
      [[ -f faraday/server/api/modules/jira.py ]] && VENV_PATH=.venv-black

      mkvirtualenv(){
        # Reset previous virtualenv
        type -t deactivate && deactivate
        rm -rf $VENV_PATH

        # Build new virtualenv with system packages
        virtualenv --system-site-packages $VENV_PATH
        source $VENV_PATH/bin/activate
        python setup.py develop
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
      export XDG_DATA_DIRS=$GSETTINGS_SCHEMAS_PATH:$XDG_DATA_DIRS
    '';
  }
