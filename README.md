# nm-file-secret-agent

A small program that can provide secrets based on configured files contents to NetworkManager.
This allows protected values to be stored outside of the `/etc/NetworkManager/system-connections` files while still configuring the connection itself there.

## Use-Case

This program was designed to allow configuration of NetworkManager connections with NixOs that rely on secrets.
The underlying problem is that, while NixOs provides options for statically configuring connection profiles (see [`networking.networkmanager.ensureProfiles.profiles` options](https://search.nixos.org/options?channel=unstable&type=packages&query=networking.networkmanager.ensureProfiles.profiles)), those settings are exposed in the nix store as world-readable.
An example for such a secret is the private-key of a wireguard connection.
NetworkManager, however, provides a mechanism for storing secrets inside an agent instead of the static configuration.
Using such an agent, secrets can be provided at runtime by an external program.

So in summary, my setup provides a connection secret (e.g. a WireGuard private-key) at `/run/secrets/wg_privkey`, the NetworkManager connection profile is configured to read the private-key from secret agents, and the here implemented program bridges the two by providing the files content at runtime.
