{ pkgs ? null }:
if pkgs != null then pkgs else import ./fallback-shell.nix
