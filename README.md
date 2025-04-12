# nm-file-secret-agent

A small program that can provide secrets based on configured files contents to NetworkManager.
This allows protected values to be stored outside of the `/etc/NetworkManager/system-connections` files while still configuring the connection itself there.

- [Source Code & Documentation](https://codeberg.org/lilly/nm-file-secret-agent)

## Use-Case

This program was designed to allow configuration of NetworkManager connections with NixOS that rely on secrets.
The underlying problem is that, while NixOS provides options for statically configuring connection profiles (see [`networking.networkmanager.ensureProfiles.profiles` options](https://search.nixos.org/options?channel=unstable&type=packages&query=networking.networkmanager.ensureProfiles.profiles)), those settings are exposed in the nix store as world-readable.
An example for such a secret is the private-key of a wireguard connection.
NetworkManager, however, provides a mechanism for storing secrets inside an agent instead of the static configuration.
Using such an agent, secrets can be provided at runtime by an external program.
This program is such an agent.

For example, my setup provides a WireGuard private-key at `/run/secrets/wg_privkey`, the NetworkManager connection profile is configured to read the private-key from secret agents, and this agent bridges the two by providing the file's content at runtime.

## CLI Usage

The provided command line interface is very small and can be queried by calling `nm-file-secret-agent --help`

```
Usage: nm-file-secret-agent [OPTIONS] --conf <CONFIG>

Options:
  -c, --conf <CONFIG>
          Path to a config file

  -v, --verbose...
          Increase program verbosity

          The default verbosity level is INFO.

  -q, --quiet...
          Decrease program verbosity

          The default verbosity level is INFO.
```


## Configuration File Reference

The configuration file must be in TOML format.
It describes a list of entries such as the listing below.

In general, each entry consists of multiple `match_` keys, determining which requests for secrets this agent responds to.
Each match is optional and can be omitted but if multiple are specified, all of them mus match in order for an entry to be considered for a request.
The `key` and `file` then determine *how* the request is answered.
`key` configures the key in the setting section for which an entry describes a value while `file` should be the path to a file from which the secret is read.

```toml
[[entry]]
match_id = "<network manager connection id (displayed as name in GUIs)>"
match_uuid = "<network manager connection uuid>"
match_type = "<network manager connection type>"
match_iface = "<interface name of the network manager connection>"
match_setting = "<name of the setting section for which secrets are requested>"
key = "<key in the setting section for which entry provides a value>"
file = "<file from which the secret value is read>"
```

### Example

Suppose, the following configuration file is used:

```toml
[[entry]]
match_type = "wireguard"
match_setting = "wireguard"
key = "private-key"
file = "/run/secrets/wg_privkey"
```

After *nm-file-secret-agent* is started, it will only respond to secret requests that
- have a `connection.type` value equal to `wireguard`
- and which are querying for secrets in the `wireguard` settings

If such a matching request is encountered, it is answered by providing the `wireguard.private-key` setting with a value taken from the file `/run/secrets/wg_privkey`.

### Note on WireGuard `preshared-key`

Due to the way Network-Manager internally stores WireGuard peer configurations, some special attention must be given to preshared-key configuration.
Given the following (compacted) NetworkManager connection configuration:

```
[wireguard-peer.<some-public-key>]
preshared-key-flags=1
```

Then, in this agents configuration file, this must be specified as:

```toml
[[entry]]
match_type = "wireguard"
match_setting = "wireguard"
key = "peers.<some-public-key>.preshared-key"
file = "/run/secrets/wg_psk"
```
