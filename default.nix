# Running nix-build will build will build Faraday using the current directory
# as source. Untracked or modified files will be used
(import ./release.nix { useLastCommit = false; }).faraday-server
