# Changelog

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
