{
  perSystem = {
    config,
    pkgs,
    inputs',
    ...
  }: {
    devShells.default = with pkgs;
      mkShell {
        packages = [
          cargo
          cmake
          rustc
          pkg-config
          protobuf
          openssl
          zlib
          rust-analyzer
          rustfmt
          libclang
          clippy
          clang-tools
          config.treefmt.build.wrapper
          # Aiken v1.1.21 for compiling governance smart contracts
          inputs'.aiken.packages.default
        ];
      };
  };
}
