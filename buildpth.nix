with (import <nixpkgs> {});

stdenv.mkDerivation {
  name = "faraday-nix.pth";
  packages = with python37Packages; [virtualenv pip pyopenssl psycopg2 pgcli pillow pygobject3 pynacl matplotlib numpy lxml ldap autobahn gssapi setproctitle simplejson pycairo cffi cairocffi bcrypt twisted];
  builder = ./buildpth.sh;
}
