(import ./default.nix).overrideAttrs (_: {
  doCheck = true;
  checkPhase = "true";
  checkInputs = with (import ./pypi2nixpkgs/nixpkgs.nix { }).python3.pkgs; [
    pylint
    factory_boy
    pytest
    pytest-factoryboy
    responses
    hypothesis
    sphinx
    pytestcov
  ];
})
