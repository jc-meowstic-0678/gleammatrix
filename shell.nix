{ pkgs ? import /nix/var/nix/profiles/per-user/root/channels/nixpkgs {} }:

pkgs.mkShell { 
  buildInputs = with pkgs; [ 
    gleam 
    erlang 
    rebar3 
  ]; 
}
