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
  in {
    packages.x86_64-linux.nm-file-secret-agent = pkgs.rustPlatform.buildRustPackage {
      name = cargoToml.package.name;
      version = cargoToml.package.version;
      src = ./.;
      cargoLock.lockFile = ./Cargo.lock;
      LD_LIBRARY_PATH = with pkgs; lib.makeLibraryPath [ dbus ];
      PKG_CONFIG_PATH = with pkgs; lib.makeSearchPathOutput "dev" "lib/pkgconfig" [ dbus ];
      nativeBuildInputs = with pkgs; [ pkg-config ];
    };

    devShells.x86_64-linux.default = pkgs.mkShell {
      LD_LIBRARY_PATH = with pkgs; lib.makeLibraryPath [ dbus ];
      PKG_CONFIG_PATH = with pkgs; lib.makeSearchPathOutput "dev" "lib/pkgconfig" [ dbus ];
      packages = with pkgs; [ cargo pkg-config ];
    };
  };
}
