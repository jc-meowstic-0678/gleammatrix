
  { pkgs ? import <nixpkgs> {} }:

  pkgs.mkShell {
    buildInputs = with pkgs; [
      gleam
      erlang
      rebar3
    ];
  }
