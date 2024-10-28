use std::{collections::HashMap, time::Duration};

use dbus::{
    arg::{Dict, PropMap, RefArg, Variant},
    blocking::{Connection, Proxy},
    Path,
};
use dbus_crossroads::{Context, Crossroads};

use crate::{agent_manager::OrgFreedesktopNetworkManagerAgentManager, mapping::MappingConfig};

/// Indication of agent capabilities
///
/// See [reference](https://networkmanager.dev/docs/api/latest/nm-dbus-types.html#NMSecretAgentCapabilities).
#[repr(u32)]
enum SecretAgentCapabilities {
    None = 0,
    #[allow(unused)]
    VpnHints = 1,
}

/// Values modifying the behavior of a GetSecrets request
///
/// See [reference](https://networkmanager.dev/docs/api/latest/nm-dbus-types.html#NMSecretAgentGetSecretsFlags)
#[repr(u32)]
enum GetSecretsFlags {
    /// No special behavior; by default no user interaction is allowed and requests for secrets are fulfilled from persistent storage, or if no secrets are available an error is returned.
    None = 0x0,
    /// allows the request to interact with the user, possibly prompting via UI for secrets if any are required, or if none are found in persistent storage.
    AllowInteraction = 0x1,
    /// explicitly prompt for new secrets from the user. This flag signals that NetworkManager thinks any existing secrets are invalid or wrong. This flag implies that interaction is allowed.
    RequestNew = 0x2,
    /// set if the request was initiated by user-requested action via the D-Bus interface, as opposed to automatically initiated by NetworkManager in response to (for example) scan results or carrier changes.
    UserRequested = 0x4,
    /// indicates that WPS enrollment is active with PBC method. The agent may suggest that the user pushes a button on the router instead of supplying a PSK.
    WbsPbcActive = 0x8,
}

pub type NestedSettingsMap = HashMap<String, PropMap>;

pub fn run(mapping: MappingConfig) -> ! {
    let mut cross = Crossroads::new();

    let iface_token = cross.register("org.freedesktop.NetworkManager.SecretAgent", |b| {
        // GetSecrets()
        b.method(
            "GetSecrets",
            (
                "connection",
                "connection_path",
                "setting_name",
                "hints",
                "flags",
            ),
            ("secrets",),
            move |_ctx: &mut Context,
                  obj: &mut MappingConfig,
                  args: (NestedSettingsMap, Path, String, Vec<String>, u32)| {
                Ok((get_secret(obj, args),))
            },
        );

        // CancelGetSecrets()
        b.method(
            "CancelGetSecrets",
            ("connection_path", "setting_name"),
            (),
            move |_ctx: &mut Context,
                  _obj: &mut MappingConfig,
                  (connection_path, setting_name): (Path, String)| {
                tracing::debug!(%connection_path, setting_name, "got CancelGetSecrets() call");
                Ok(())
            },
        );

        // SaveSecrets()
        b.method(
            "SaveSecrets",
            ("connection", "connection_path"),
            (),
            move |_ctx: &mut Context,
                  _obj: &mut MappingConfig,
                  (_connection, connection_path): (NestedSettingsMap, Path)| {
                tracing::debug!(%connection_path, "got SaveSecrets() call");
                Ok(())
            },
        );

        // DeleteSecrets()
        b.method(
            "DeleteSecrets",
            ("connection", "connection_path"),
            (),
            move |_ctx: &mut Context,
                  _obj: &mut MappingConfig,
                  (_connection, connection_path): (NestedSettingsMap, Path)| {
                tracing::debug!(%connection_path, "got DeleteSecrets() call");
                Ok(())
            },
        );
    });

    cross.insert(
        "/org/freedesktop/NetworkManager/SecretAgent",
        &[iface_token],
        mapping,
    );

    tracing::debug!("Connecting to system bus");
    let conn = Connection::new_system().expect("Could not connect to the system D-Bus daemon");
    tracing::debug!("Connected to bus as {}", conn.unique_name());

    let network_manager = conn.with_proxy(
        "org.freedesktop.NetworkManager",
        "/org/freedesktop/NetworkManager/AgentManager",
        Duration::from_secs(1),
    );
    register_agent(&network_manager);

    tracing::info!("Serving secret service on system bus");
    cross.serve(&conn).expect("Could not run D-Bus service");
    unreachable!();
}

fn register_agent(proxy: &Proxy<&Connection>) {
    tracing::debug!("Registering secret agent with NetworkManager");
    proxy
        .register_with_capabilities("nm-file-secret-agent", SecretAgentCapabilities::None as u32)
        .expect("Could not register as secret agent with NetworkManager");
}

fn get_secret(
    mapping: &mut MappingConfig,
    (connection, _connection_path, setting_name, hints, flags): (
        NestedSettingsMap,
        Path,
        String,
        Vec<String>,
        u32,
    ),
) -> NestedSettingsMap {
    let conn_id = &connection["connection"]["id"]
        .as_str()
        .expect("Connection property is not a string");
    let conn_uuid = connection["connection"]["uuid"]
        .as_str()
        .expect("Connection property is not a string");
    let conn_type = connection["connection"]["type"]
        .as_str()
        .expect("Connection property is not a string");
    let iface_name = connection["connection"]["interface-name"]
        .as_str()
        .expect("Connection property is not a string");

    tracing::info!(
        connectionId = conn_id,
        connectionUuid = conn_uuid,
        connectionType = conn_type,
        ifaceName = iface_name,
        settingName = setting_name,
        ?hints,
        ?flags,
        "Received getSecrets() call from NetworkManager"
    );

    // abort on unsupported flags
    if (flags & GetSecretsFlags::RequestNew as u32) == GetSecretsFlags::RequestNew as u32 {
        panic!("NetworkManager requested new credentials which cannot be provided by this agent");
    }
    if (flags & GetSecretsFlags::WbsPbcActive as u32) == GetSecretsFlags::WbsPbcActive as u32 {
        panic!("NetworkManager requested a WPA action to be performed which is not supported by this agent");
    }

    // fetch matching secret entries
    let secrets = mapping.get_secrets(conn_id, conn_uuid, conn_type, iface_name, &setting_name);

    if !secrets.is_empty() {
        // encode a result dataset
        let mut result = NestedSettingsMap::new();
        result.insert(setting_name.clone(), HashMap::new());
        for (key, secret_value) in secrets.iter() {
            result
                .get_mut(&setting_name)
                .unwrap()
                .insert(key.to_owned(), Variant(Box::new(secret_value.to_owned())));
        }

        // warn if NetworkManager hinted at values that are not provided
        for hint in hints.iter() {
            if result[&setting_name]
                .keys()
                .find(|&key| key == hint)
                .is_none()
            {
                tracing::warn!("Call from NetworkManager hinted at required key {setting_name}.{hint} and while nm-file-secret-agent has secret entries configured in the {setting_name} section, the key {hint} is missing");
            }
        }

        let matched_names = secrets
            .iter()
            .map(|(key, _)| format!("{}.{}", &setting_name, &key))
            .collect::<Vec<_>>()
            .join(", ");
        tracing::info!("returning secrets values for {matched_names}");
        result
    } else {
        tracing::info!(
            "no entries were configured that match the request so no secrets are returned"
        );
        NestedSettingsMap::default()
    }
}
