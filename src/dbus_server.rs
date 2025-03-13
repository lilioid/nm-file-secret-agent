use std::{collections::HashMap, ops::Deref, time::Duration};

use anyhow::Context;
use dbus::{
    arg::{PropMap, RefArg, Variant},
    blocking::Connection,
    MethodErr, Path,
};
use dbus_crossroads::{Context as DbusContext, Crossroads};

use crate::dbus_bus_manager::OrgFreedesktopDBus;
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
    #[allow(dead_code)]
    None = 0x0,
    /// allows the request to interact with the user, possibly prompting via UI for secrets if any are required, or if none are found in persistent storage.
    #[allow(dead_code)]
    AllowInteraction = 0x1,
    /// explicitly prompt for new secrets from the user. This flag signals that NetworkManager thinks any existing secrets are invalid or wrong. This flag implies that interaction is allowed.
    RequestNew = 0x2,
    /// set if the request was initiated by user-requested action via the D-Bus interface, as opposed to automatically initiated by NetworkManager in response to (for example) scan results or carrier changes.
    #[allow(dead_code)]
    UserRequested = 0x4,
    /// indicates that WPS enrollment is active with PBC method. The agent may suggest that the user pushes a button on the router instead of supplying a PSK.
    #[allow(dead_code)]
    WbsPbcActive = 0x8,
}

pub type NestedSettingsMap = HashMap<String, PropMap>;

#[derive(Debug)]
struct Server {
    known_nm_names: Vec<String>,
    mapping: MappingConfig,
}

pub fn run(mapping: MappingConfig) -> anyhow::Result<()> {
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
            move |ctx: &mut DbusContext,
                  obj: &mut Server,
                  args: (NestedSettingsMap, Path, String, Vec<String>, u32)| {
                tracing::debug!("got getSecrets() call");
                verify_access(ctx, &obj.known_nm_names)?;
                match get_secret(&mut obj.mapping, args) {
                    Ok(secrets) => Ok((secrets,)),
                    Err(e) => {
                        tracing::error!(error = %e, "Could not execute getSecrets()");
                        Err(MethodErr::failed(&e))
                    }
                }
            },
        );

        // CancelGetSecrets()
        b.method(
            "CancelGetSecrets",
            ("connection_path", "setting_name"),
            (),
            move |_ctx: &mut DbusContext,
                  _obj: &mut Server,
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
            move |_ctx: &mut DbusContext,
                  _obj: &mut Server,
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
            move |_ctx: &mut DbusContext,
                  _obj: &mut Server,
                  (_connection, connection_path): (NestedSettingsMap, Path)| {
                tracing::debug!(%connection_path, "got DeleteSecrets() call");
                Ok(())
            },
        );
    });

    tracing::debug!("Connecting to system bus");
    let conn = Connection::new_system().context("Could not connect to the system D-Bus daemon")?;
    tracing::debug!("Connected to bus as {}", conn.unique_name());

    let known_nm_names = get_nm_names(&conn)?;
    register_agent(&conn)?;

    cross.insert(
        "/org/freedesktop/NetworkManager/SecretAgent",
        &[iface_token],
        Server {
            known_nm_names,
            mapping,
        },
    );

    tracing::info!("Registered with NetworkManager; now serving D-Bus API");
    cross.serve(&conn).context("Could not run D-Bus service")?;

    unreachable!();
}

fn register_agent(conn: &Connection) -> anyhow::Result<()> {
    tracing::debug!("Registering secret agent with NetworkManager");
    let proxy = conn.with_proxy(
        "org.freedesktop.NetworkManager",
        "/org/freedesktop/NetworkManager/AgentManager",
        Duration::from_secs(1),
    );
    proxy
        .register_with_capabilities("nm-file-secret-agent", SecretAgentCapabilities::None as u32)
        .context("Could not register as secret agent with NetworkManager")?;
    Ok(())
}

fn get_nm_names(conn: &Connection) -> anyhow::Result<Vec<String>> {
    tracing::debug!(
        "Querying DBus bus manager for all names that NetworkManager operates on the bus"
    );
    let proxy = conn.with_proxy(
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        Duration::from_secs(5),
    );
    let name = "org.freedesktop.NetworkManager".to_string();
    let name_owner = proxy
        .get_name_owner(&name)
        .context("Could not query owner of name org.freedesktop.NetworkManager")?;

    Ok(vec![name_owner, name])
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
) -> anyhow::Result<NestedSettingsMap> {
    let conn_id = &connection["connection"]["id"]
        .as_str()
        .context("Connection property connection.id is not a string")?;
    let conn_uuid = connection["connection"]["uuid"]
        .as_str()
        .context("Connection property connection.uuid is not a string")?;
    let conn_type = connection["connection"]["type"]
        .as_str()
        .context("Connection property connection.type is not a string")?;
    // The interface name is not always present. If it is present, it should be a string.
    let iface_name = if let Some(iface) = connection["connection"].get("interface-name") {
        Some(
            iface
                .as_str()
                .context("Connection property connection.interface-name is not a string")?,
        )
    } else {
        None
    };

    tracing::info!(
        connectionId = conn_id,
        connectionUuid = conn_uuid,
        connectionType = conn_type,
        ifaceName = iface_name,
        settingName = setting_name,
        ?hints,
        ?flags,
        "Resolving secret request with configured mapping"
    );

    // abort on unsupported flags
    if (flags & GetSecretsFlags::RequestNew as u32) == GetSecretsFlags::RequestNew as u32 {
        return Err(anyhow::anyhow!(
            "NetworkManager requested new credentials which cannot be provided by this agent"
        ));
    }

    // fetch matching secret entries
    let secrets = mapping
        .get_secrets(conn_id, conn_uuid, conn_type, iface_name, &setting_name)
        .context("Could not fetch secrets")?;

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
            if !result[&setting_name].keys().any(|key| key == hint) {
                tracing::warn!("Call from NetworkManager hinted at required key {setting_name}.{hint} and while nm-file-secret-agent has secret entries configured in the {setting_name} section, the key {hint} is missing");
            }
        }

        let matched_names = secrets
            .iter()
            .map(|(key, _)| format!("{}.{}", &setting_name, &key))
            .collect::<Vec<_>>()
            .join(", ");
        tracing::info!("returning secrets values for {matched_names}");
        Ok(result)
    } else {
        tracing::info!(
            "no entries were configured that match the request so no secrets are returned"
        );
        Ok(NestedSettingsMap::default())
    }
}

/// Verify that NetworkManager was the one who called
fn verify_access(ctx: &mut DbusContext, known_nm_names: &[String]) -> Result<(), MethodErr> {
    tracing::debug!("Verifying that it was NetworkManager that called us");
    let sender = ctx.message().sender();
    match sender {
        None => {
            tracing::debug!("Denying method access for sender without a bus name");
            Err(MethodErr::failed("Access Denied"))
        }
        Some(sender) => match known_nm_names.iter().any(|i| i.as_str() == sender.deref()) {
            true => Ok(()),
            false => {
                tracing::debug!("Denying method access for sender that is not NetworkManager");
                Err(MethodErr::failed("Access Denied"))
            }
        },
    }
}
