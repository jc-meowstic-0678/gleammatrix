#!/bin/bash
# Gleam Matrix Server - Quick syntax check without Nix dependencies

echo "=== Gleam Syntax Check ==="

# Check if gleam is available in PATH
if command -v gleam &> /dev/null; then
  echo "✓ Found gleam CLI"
  
  # Run syntax check only (no build)
  gleam check
  
else
  echo "✗ gleam CLI not found in PATH"
  echo ""
  echo "Please install gleam and add it to your PATH:"
  echo "  macOS: brew install gleam"
  echo "  Linux: curl -sfL https://gleam.run/install.sh | sh"
  echo "  npm:   npm install -g gleam"
  echo ""
  echo "Or configure \$NIX_PATH with nixpkgs and re-run."
fi
