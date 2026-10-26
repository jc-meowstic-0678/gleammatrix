#!/bin/bash
# Gleam Matrix Server - Verify syntax without Nix dependencies

cd /var/projects/gleammatrix

echo "=== Gleam Syntax Verification ==="
echo ""

# List all source files to review
echo "📁 Project Source Files:"
find src -name "*.gleam" | sort
echo ""

# Check if gleam CLI is available in PATH
if command -v gleam &> /dev/null; then
  echo "✅ Found Gleam CLI in PATH"
  echo "   Version: $(gleam --version)"
  echo ""
  
  # Run syntax check only (no build dependencies)
  echo "🔍 Running gleam check..."
  gleam check
  
else
  echo "⚠️ Gleam CLI not found in PATH"
  echo ""
  echo "Quick Install Options:"
  echo "  🍺 macOS: brew install gleam"
  echo "  🐧 Linux: curl -sfL https://gleam.run/install.sh | sh"
  echo "  💻 npm:   npm install -g gleam"
  echo ""
  echo "Or set up Nix with:"
  echo "  export NIX_PATH=nixpkgs=/nix/var/nix/profiles/per-user/root/channels/nixpkgs"
fi
