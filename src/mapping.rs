//! Middle-Layer between dbus and the configuration file which maps requests to secrets

use crate::config::{AgentConfig, MappingEntry};
use crate::dbus::{GetSecretsFlags, NestedSettingsMap};
use anyhow::Context;
use dbus::arg::{PropMap, RefArg, Variant};
use std::collections::{HashMap, HashSet};

/// A plain <key> -> <valu> secret
#[derive(Debug, Clone, Eq, PartialEq)]
struct Secret {
    key: String,
    value: String,
}

impl TryFrom<MappingEntry> for Secret {
    type Error = anyhow::Error;

    fn try_from(value: MappingEntry) -> Result<Self, Self::Error> {
        let secret_value = value.read()?;
        Ok(Self {
            key: value.key,
            value: secret_value,
        })
    }
}

/// Handle the get_secret() request from Network-Manager
///
/// ## Arguments
///
/// - *config* is the configuration of this application. It contains the configured secrets.
/// - A tuple which contains data from Network-Managers request
///     - A [NestedSettingsMap] for the existing connection profile data
///     - The name of the setting (or section) for which secrets are requested
///     - Additional hints and flags for the request
///
/// ## Return
///
/// This function returns a new [NestedSettingsMap] containing all secrets that this agent can provide
/// for the requested setting.
pub fn get_secret(
    config: &mut AgentConfig,
    (connection_profile, requested_setting, hints, flags): (
        &NestedSettingsMap,
        &str,
        &[String],
        u32,
    ),
) -> anyhow::Result<NestedSettingsMap> {
    // extract needed data from the connection profile so that we can match on it
    let conn_id = &connection_profile["connection"]["id"]
        .as_str()
        .context("Connection property connection.id is not a string")?;
    let conn_uuid = connection_profile["connection"]["uuid"]
        .as_str()
        .context("Connection property connection.uuid is not a string")?;
    let conn_type = connection_profile["connection"]["type"]
        .as_str()
        .context("Connection property connection.type is not a string")?;

    // the interface name is not always present. If it is present, it should be a string.
    let iface_name = match connection_profile["connection"].get("interface-name") {
        None => None,
        Some(iface_name) => Some(
            iface_name
                .as_str()
                .context("Connection property connection.interface-name is not a string")?,
        ),
    };

    tracing::info!(
        connectionId = conn_id,
        connectionUuid = conn_uuid,
        connectionType = conn_type,
        ifaceName = iface_name,
        settingName = requested_setting,
        ?hints,
        ?flags,
        "Resolving secret request with configured mappings"
    );

    // abort on unsupported flags
    if (flags & GetSecretsFlags::RequestNew as u32) == GetSecretsFlags::RequestNew as u32 {
        return Err(anyhow::anyhow!(
            "NetworkManager requested new credentials which cannot be provided by this agent"
        ));
    }

    // fetch matching secret entries
    let secrets = config
        .find_matching_secrets(conn_id, conn_uuid, conn_type, iface_name, requested_setting)
        .iter()
        .map(|i| i.to_owned().try_into())
        .collect::<anyhow::Result<Vec<Secret>>>()
        .context("Could not read secret content from configured files")?;

    // abort early if not secrets match
    if secrets.is_empty() {
        tracing::info!(
            "no entries were configured that match the request so no secrets are returned"
        );
        return Ok(NestedSettingsMap::default());
    }

    // encode a result dataset with the correct encoder
    let (settings, inserted_keys) = match requested_setting {
        "wireguard" => encode_wireguard_secrets(&secrets),
        _ => encode_generic_secrets(&secrets),
    };

    let mut result = NestedSettingsMap::new();
    result.insert(requested_setting.to_owned(), settings);

    // warn if NetworkManager hinted at values that are not provided
    for hint in hints.iter() {
        if !inserted_keys.contains(hint) {
            tracing::warn!(
                "Call from NetworkManager hinted at required key {requested_setting}.{hint} and \
                    while nm-file-secret-agent has secret entries configured in the \
                    {requested_setting} section, {hint} is not configured"
            );
        }
    }

    // combine all found secrets into one result
    let matched_names = secrets
        .iter()
        .map(|entry| format!("{}.{}", &requested_setting, &entry.key))
        .collect::<Vec<_>>()
        .join(", ");

    tracing::info!("returning secrets values for {matched_names}");
    Ok(result)
}

/// Encode secrets in a way that is suitable for most Network-Manager secrets.
///
/// Given a list of secrets, they are encoded in a [PropMap] that simply maps from the secret's
/// configured `key` property to its string value.
///
/// No special attention is given to keys that contain dots or other special characters and no
/// nested PropMaps are ever created.
fn encode_generic_secrets(secrets: &[Secret]) -> (PropMap, HashSet<String>) {
    let map = secrets
        .iter()
        .map(|entry| (entry.key.clone(), Variant(entry.value.box_clone())))
        .collect::<PropMap>();

    let keys = map.keys().cloned().collect();
    (map, keys)
}

/// Encode secrets in a way that is suited for WireGuard settings.
///
/// Due to the way Network-Manager internally represents WireGuard settings, especially peer configurations,
/// special attention is required to encode such secrets.
fn encode_wireguard_secrets(secrets: &[Secret]) -> (PropMap, HashSet<String>) {
    let mut props = PropMap::new();
    let mut inserted_keys = HashSet::new();
    let mut peers = HashMap::<String, HashMap<String, String>>::new();

    for i_secret in secrets.iter() {
        let keyparts: Vec<&str> = i_secret.key.split(".").collect();

        match keyparts[..] {
            ["peers", pubkey, subkey] => {
                // Either retrieve the already-existing peer property map, or create a new one and
                // return that
                let peer = match peers.get_mut(pubkey) {
                    Some(p) => p,
                    None => {
                        peers.insert(pubkey.to_owned(), HashMap::new());
                        peers.get_mut(pubkey).expect("just inserted settings map")
                    }
                };

                peer.insert(subkey.to_owned(), i_secret.value.to_owned());
            }
            _ => {
                // The simple case, a top-level key
                props.insert(i_secret.key.to_owned(), Variant(i_secret.value.box_clone()));
            }
        }

        inserted_keys.insert(i_secret.key.to_owned());
    }

    // For peer-specific WireGuard secrets, D-Bus actually expects
    // a list of hashmaps, i.e. in D-Bus speak: array of
    // Dict<String, Variant>, aka `aa{sv}`. The `public-key` property
    // _must_ be set, so that NetworkManager can identify the correct peer.
    //
    // See also nm_setting_wireguard_class_init() in
    // NetworkManager/src/libnm-core-impl/nm-setting-wireguard.c
    //
    // We use a sane structure above and convert it here to D-Bus weirdness,
    // for simplicity.
    if !peers.is_empty() {
        let peerlist = peers
            .iter()
            .map(|(pubkey, values)| {
                let mut propmap = values
                    .iter()
                    .map(|(k, v)| (k.to_owned(), Variant(v.box_clone())))
                    .collect::<PropMap>();
                propmap.insert("public-key".to_owned(), Variant(pubkey.box_clone()));
                propmap
            })
            .collect::<Vec<PropMap>>();

        props.insert("peers".to_owned(), Variant(peerlist.box_clone()));
    }

    (props, inserted_keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dbus::arg::RefArg;

    #[test]
    fn encode_generic_secret() {
        let (secrets, inserted_keys) = encode_generic_secrets(&[
            Secret {
                key: "psk".into(),
                value: "FOO_BAR".into(),
            },
            Secret {
                key: "secret2".into(),
                value: "FOO_BAR2".into(),
            },
        ]);

        assert_eq!(secrets.signature(), "a{sv}".into());
        assert!(secrets.contains_key("psk"));
        assert!(secrets.contains_key("secret2"));
        assert_eq!(
            inserted_keys,
            ["psk".to_string(), "secret2".to_string()]
                .into_iter()
                .collect()
        )
    }

    #[test]
    /// See also for more information:
    /// https://codeberg.org/lilly/nm-file-secret-agent/issues/1#issuecomment-2939232
    fn encode_wireguard_secret_with_preshared_key() {
        let (secrets, inserted_keys) = encode_wireguard_secrets(&[
            Secret {
                key: "private-key".into(),
                value: "PRIV_KEY_FOOR".into(),
            },
            Secret {
                key: "peers.PUB_KEY_BAR.preshared-key".into(),
                value: "PRESHARED_KEY_FOOR_BAR".into(),
            },
        ]);

        assert!(secrets.contains_key("private-key"));
        assert!(secrets.contains_key("peers"));
        assert_eq!(secrets.signature(), "a{sv}".into());

        assert!(inserted_keys.contains("private-key"));
        assert!(inserted_keys.contains("peers.PUB_KEY_BAR.preshared-key"));
    }
}
