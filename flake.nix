{
  description = "YourApp";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    flake-parts.url = "github:hercules-ci/flake-parts";
    crane.url = "github:ipetkov/crane";
    fenix.url = "github:nix-community/fenix";
    fenix.inputs.nixpkgs.follows = "nixpkgs";
    treefmt-nix.url = "github:numtide/treefmt-nix";
    treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";

    # Hayate for Plutus transaction building
    hayate.url = "github:disassembler/hayate";
    hayate.inputs.nixpkgs.follows = "nixpkgs";

    # Aiken smart contract compiler
    aiken.url = "github:aiken-lang/aiken/v1.1.21";
    # Don't follow nixpkgs - let Aiken use its own nixos-unstable + rust-overlay
  };

  outputs = {
    self,
    flake-parts,
    nixpkgs,
    ...
  } @ inputs: let
    inherit ((import ./flake/lib.nix {inherit inputs;}).flake.lib) recursiveImports;
  in
    flake-parts.lib.mkFlake {inherit inputs;} {
      imports =
        recursiveImports [
          ./flake
          ./perSystem
        ]
        ++ [
          inputs.treefmt-nix.flakeModule
        ];
      systems = [
        "x86_64-linux"
      ];
    }
    // {
      inherit inputs;
    };
}
