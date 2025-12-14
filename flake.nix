{
  inputs = {
    crane.url = "github:ipetkov/crane";
    systems.url = "github:nix-systems/default";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-parts = {
      inputs.nixpkgs-lib.follows = "nixpkgs";
      url = "github:hercules-ci/flake-parts";
    };
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    treefmt-nix.url = "github:numtide/treefmt-nix";
  };

  outputs =
    inputs@{ flake-parts, systems, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } (
      { ... }:
      {
        systems = import systems;

        imports = [ inputs.treefmt-nix.flakeModule ];

        perSystem =
          {
            lib,
            pkgs,
            system,
            ...
          }:
          {
            _module.args.pkgs = import inputs.nixpkgs {
              inherit system;
              overlays = [
                inputs.fenix.overlays.default
                (self: _: { crane = (inputs.crane.mkLib self).overrideToolchain self.fenix.stable.toolchain; })
              ];
            };

            treefmt.programs = {
              actionlint.enable = true;
              deadnix.enable = true;
              mdformat.enable = true;
              nixfmt = {
                enable = true;
                strict = true;
              };
              rustfmt.enable = true;
              statix.enable = true;
              taplo.enable = true;
              yamlfmt.enable = true;
            };

            devShells.default =
              let
                linkedInputs = with pkgs; [
                  clang
                  mold
                  pkg-config
                ];
              in
              pkgs.crane.devShell {
                packages =
                  (with pkgs; [
                    cargo-edit
                    cargo-machete
                    cargo-nextest
                    cargo-rdme
                    cargo-release
                    cargo-workspaces
                  ])
                  ++ linkedInputs;

                LD_LIBRARY_PATH = linkedInputs |> lib.makeLibraryPath;
              };
          };
      }
    );
}
