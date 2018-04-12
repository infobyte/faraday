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
  hypothesis = python.overrideDerivation super.hypothesis (old: {
    propagatedBuildInputs = (builtins.filter
      (drv: drv.name != self.attrs.name)
      old.propagatedBuildInputs);
  });
  attrs = python.overrideDerivation super.attrs (old: {
    propagatedBuildInputs = (builtins.filter
      (drv: drv.name != self.hypothesis.name && drv.name != self.pytest.name)
      old.propagatedBuildInputs);
  });
}
