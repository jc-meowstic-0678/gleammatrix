{ buildInputs ? [ ] }: rec {
  name = "gleam-matrix-server-env";
  
  shellHook = ''
    echo "Gleam Matrix Server - Minimal Environment"
    echo "This environment expects system gleam to be available in \$PATH"
    
    if command -v gleam >/dev/null 2>&1; then
      gleam --version
    else
      echo "WARNING: gleam not found in PATH"
      echo "Install gleam via: https://gleam.run/getting-started/installing/"
    fi
  '';
  
  inherit buildInputs shellHook;
}
