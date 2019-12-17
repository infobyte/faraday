with (import <nixpkgs> {});

stdenv.mkDerivation {
  name = "faraday-nix.pth";
  packages = with python37Packages; [virtualenv pip pyopenssl psycopg2 pillow pygobject3 pynacl matplotlib lxml ldap autobahn gssapi setproctitle simplejson pycairo  ];
  builder = ./buildpth.sh;
}
