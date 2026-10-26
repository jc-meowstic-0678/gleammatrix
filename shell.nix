{ pkgs ? import /nix/var/nix/profiles/default/channels/nixpkgs {} }:

pkgs.mkShell { 
  buildInputs = with pkgs; [ 
    gleam 
    erlang 
    rebar3 
  ]; 
}
