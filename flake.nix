{
  description = "sandbox-rs - Linux process sandbox library in Rust";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        rust = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" ];
          targets = [ "x86_64-unknown-linux-gnu" ];
        };

      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rust
            cargo-audit
            cargo-edit
            cargo-outdated
            cargo-tarpaulin
            cargo-watch
            pkg-config
            openssl
            gcc
            cmake
            gnumake
            git
            curl
            wget
            jq
            yq
            groff
            strace
            ltrace
            gdb
            nixpkgs-fmt
          ];

          shellHook = ''
            export RUST_BACKTRACE=1
            export CARGO_INCREMENTAL=1
            echo "sandbox-rs development environment loaded"
            echo "Available commands:"
            echo "  cargo build       - Build the library"
            echo "  cargo test        - Run tests (some require sudo)"
            echo "  cargo doc         - Build documentation"
            echo "  cargo fmt         - Format code"
            echo "  cargo clippy      - Run linter"
            echo "  cargo tarpaulin   - Generate coverage report"
            echo ""
            echo "For full sandbox isolation, some commands require root:"
            echo "  sudo cargo test"
            echo "  sudo cargo run --example basic_sandbox"
          '';
        };

        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "sandbox-rs";
          version = "0.1.0";

          src = ./.;

          cargoHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

          nativeBuildInputs = with pkgs; [
            pkg-config
            cmake
            gnumake
          ];

          buildInputs = with pkgs; [
            openssl
          ];

          meta = {
            description = "Linux sandbox library in rust";
            homepage = "https://github.com/ErickJ3/sandbox-rs";
            license = pkgs.lib.licenses.mit;
            maintainers = [ ];
          };
        };
      }
    );
}
