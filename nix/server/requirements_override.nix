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
    buildInputs = old.buildInputs ++ [ self.m2r self."setuptools-scm" ];
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
  "python-dateutil" = python.overrideDerivation super."python-dateutil" (old: {
    buildInputs = old.buildInputs ++ [ self."setuptools-scm" ];
  });
  "pytest" = python.overrideDerivation super."pytest" (old: {
    buildInputs = old.buildInputs ++ [ self."setuptools-scm" ];
  });
  "Flask-Security" = python.overrideDerivation super."Flask-Security" (old: {
    buildInputs = old.buildInputs ++ [ self."pytest-runner" ];
  });
  "pytest-runner" = python.overrideDerivation super."pytest-runner" (old: {
    buildInputs = old.buildInputs ++ [ self."setuptools-scm" ];
  });
}
