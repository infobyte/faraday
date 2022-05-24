# WARNING: This file was automatically generated. You should avoid editing it.
# If you run pynixify again, the file will be either overwritten or
# deleted, and you will lose the changes you made to it.

{ overlays ?
  [ ]
, ...
}@args:
let
  pynixifyOverlay =
    self: super: {
      python2 =
        super.python2.override {
          inherit
            packageOverrides;
        };
      python27 =
        super.python27.override {
          inherit
            packageOverrides;
        };
      python3 =
        super.python3.override {
          inherit
            packageOverrides;
        };
      python35 =
        super.python35.override {
          inherit
            packageOverrides;
        };
      python36 =
        super.python36.override {
          inherit
            packageOverrides;
        };
      python37 =
        super.python37.override {
          inherit
            packageOverrides;
        };
      python38 =
        super.python38.override {
          inherit
            packageOverrides;
        };
      python39 =
        super.python39.override {
          inherit
            packageOverrides;
        };
      python310 =
        super.python310.override {
          inherit
            packageOverrides;
        };
    };

  nixpkgs =
    <nixpkgs>;

  packageOverrides =
    self: super:
    { };

in import
nixpkgs
(args
  // {
    overlays =
      [
        pynixifyOverlay
      ]
      ++ overlays;
  })
