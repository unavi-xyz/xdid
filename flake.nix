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
      { ... }: {
        systems = import systems;

        imports = [ inputs.treefmt-nix.flakeModule ];

        perSystem =
          {
            lib,
            pkgs,
            system,
            ...
          }:
          let
            toolchain =
              with inputs.fenix.packages.${system};
              combine [
                complete.toolchain
                targets.wasm32-unknown-unknown.latest.rust-std
              ];

            linkedInputs = with pkgs; [
              clang
              lld
              pkg-config
            ];

            # crane's Cargo filter keeps only *.rs and Cargo.{toml,lock}, dropping the
            # JSON test fixtures and deny.toml.
            src = lib.cleanSourceWith {
              src = ./.;
              filter =
                path: type:
                lib.hasSuffix ".json" path
                || lib.hasSuffix "/deny.toml" path
                || pkgs.crane.filterCargoSources path type;
            };

            commonArgs = {
              inherit src;
              strictDeps = true;
              nativeBuildInputs = linkedInputs;
            };

            cargoArtifacts = pkgs.crane.buildDepsOnly commonArgs;
          in
          {
            _module.args.pkgs = import inputs.nixpkgs {
              inherit system;
              overlays = [
                inputs.fenix.overlays.default
                (self: _: { crane = (inputs.crane.mkLib self).overrideToolchain toolchain; })
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
              rustfmt = {
                enable = true;
                package = toolchain;
              };
              statix.enable = true;
              taplo.enable = true;
              yamlfmt.enable = true;
            };

            checks = {
              clippy = pkgs.crane.cargoClippy (
                commonArgs
                // {
                  inherit cargoArtifacts;
                  cargoClippyExtraArgs = "--all-targets --all-features -- --deny warnings";
                }
              );

              test = pkgs.crane.cargoNextest (
                commonArgs
                // {
                  inherit cargoArtifacts;
                  cargoNextestExtraArgs = "--all-features";
                  # reqwest's platform verifier needs a trust store; the sandbox has none.
                  SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
                }
              );

              deny = pkgs.crane.cargoDeny commonArgs;

              doc = pkgs.crane.cargoDoc (
                commonArgs
                // {
                  inherit cargoArtifacts;
                  cargoDocExtraArgs = "--no-deps --all-features";
                  RUSTDOCFLAGS = "--deny warnings";
                }
              );
            };

            devShells.default = pkgs.crane.devShell {
              packages =
                (with pkgs; [
                  cargo-deny
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
