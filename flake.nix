{
  description = "NetworkManager secret agent that responds with the content of preconfigured files^";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  };

  outputs = { self, nixpkgs }:
  let
    pkgs = import nixpkgs { system = "x86_64-linux"; };
    lib = nixpkgs.outputs.lib;
    cargoToml = (builtins.fromTOML (builtins.readFile ./Cargo.toml));
  in rec {
    packages.x86_64-linux = rec {
      default = nm-file-secret-agent;
      nm-file-secret-agent = pkgs.rustPlatform.buildRustPackage {
        name = cargoToml.package.name;
        version = cargoToml.package.version;
        src = ./.;
        cargoLock.lockFile = ./Cargo.lock;
        buildInputs = with pkgs; [ dbus ];
        nativeBuildInputs = with pkgs; [ pkg-config ];
        meta = {
          description = cargoToml.package.description;
          mainProgram = cargoToml.package.name;
          homepage = cargoToml.package.homepage;
          license = lib.licenses.mit;
          maintainers = with lib.maintainers; [ lilioid ];
        };
      };
    };

    nixosModules.default = import nix/module.nix packages;

    devShells.x86_64-linux.default = pkgs.mkShell {
      LD_LIBRARY_PATH = with pkgs; lib.makeLibraryPath [ dbus ];
      PKG_CONFIG_PATH = with pkgs; lib.makeSearchPathOutput "dev" "lib/pkgconfig" [ dbus ];
      packages = with pkgs; [ cargo rustfmt pkg-config pre-commit ];
    };
  };
}
