{ pkgs, python }:

self: super: {
  # Twisted = python.overrideDerivation super.Twisted (old: {
  #   propagatedBuildInputs = (builtins.filter
  #     (drv: drv.name != self.Automat.name && drv.name != self.incremental.name)
  #     old.propagatedBuildInputs);
  # });
  Automat = python.overrideDerivation super.Automat (old: {
    propagatedBuildInputs = (builtins.filter
      (drv: drv.name != self.Twisted.name)
      old.propagatedBuildInputs);
  });
  incremental = python.overrideDerivation super.incremental (old: {
    propagatedBuildInputs = (builtins.filter
      (drv: drv.name != self.Twisted.name)
      old.propagatedBuildInputs);
  });
}
