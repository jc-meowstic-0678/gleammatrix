# Gleam Matrix Server - Environment Setup

## Quick Start (without nix)

This project includes a fallback environment that works with system-installed gleam:

```bash
# Install gleam first (if needed)
# macOS: brew install gleam
# Linux: curl -sfL https://gleam.run/install.sh | sh
# npm:   npm install -g gleam

# Check syntax
gleam check

# Run tests
gleam test

# Build the project
gleam build
```

## Nix Environment

If you prefer using nix:

```bash
# Ensure nixpkgs is accessible
export NIX_PATH=nixpkgs=https://nixos.org/channels/nixos-unstable

# Enter shell with all dependencies
nix-shell

# Then run gleam commands inside the shell
gleam check
gleam test
```

## Troubleshooting

- **Missing nixpkgs**: The environment will fall back to requiring system gleam
- **Permission denied on _build/**: Remove `_build` directory and rebuild
- **Gleam version mismatch**: Use Gleam 1.0+ (check `gleam.toml` for minimum version)

## Development Workflow

```bash
# Format code
gleam format src/

# Check all files
gleam check

# Run tests with coverage
gleam test --coverage

# Build release
gleam build --release
```
