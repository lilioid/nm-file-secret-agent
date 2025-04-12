# Changelog

## v1.1.0

### New Features

- Add support for serving WireGuard preshared-keys.
  Network-Manager handles WireGuard configurations in a special way that is not compatible with the way this agent responded to GetSecret() requests.
  Many thanks to Christoph Heiss <christoph@c8h4.io> (@c8h4) for discovering this bug, debugging it and implementing the final feature.
  See the updated README.md for details on how to use it.

- Handle restart of NetworkManager and reconnect to new instance automatically.

### Misc

- update dependencies to newest versions
- improve internal code structure, logging and error handling
- improve development experience through better flake configuration and other configuration files


## v1.0.1

### Fixes

- Allow the agent to provide WiFi secrets even if WPS action is requested.
  It was discovered that NetworkManager sets the `WpsPbcActive` flag even if WPS is not actually required for WiFi authentication.
  Thanks to @hannes-hochreiner for fixing this by returning WiFi secrets regardless of that flag.

- Remove all calls to `panic!()` which would lead to an agent crash.
  Previously, some requests from NetworkManager which were not structured in a way that was expected could lead to nm-file-secret-agent crashing instead of just logging an error.
  Thanks to @hannes-hochreiner for noticing and fixing this.

### Misc (internal and maintenance work)

- update rust dependencies
- align flake package definition with that from nixpkgs
