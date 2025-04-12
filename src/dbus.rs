//! Code for handling D-Bus related functionality
//!
//! This involves connecting the agent to D-Bus, registering it with Network-Manager and handling
//! dispatching requests received via D-Bus to internal functions.

use anyhow::Context;
use dbus::{arg::PropMap, blocking::Connection, MethodErr, Path};
use dbus_crossroads::{Context as DbusContext, Crossroads};
use std::{collections::HashMap, ops::Deref, time::Duration};

use crate::generated::dbus_bus_manager::OrgFreedesktopDBus;
use crate::{
    config::AgentConfig, generated::agent_manager::OrgFreedesktopNetworkManagerAgentManager,
    mapping,
};

/// Indication of agent capabilities
///
/// See [reference](https://networkmanager.dev/docs/api/latest/nm-dbus-types.html#NMSecretAgentCapabilities).
#[repr(u32)]
pub enum SecretAgentCapabilities {
    /// The agent supports no special capabilities
    None = 0,
    #[allow(unused)]
    /// The agent supports passing hints to VPN plugin authentication dialogs.
    VpnHints = 1,
}

/// Values modifying the behavior of a GetSecrets request
///
/// See [reference](https://networkmanager.dev/docs/api/latest/nm-dbus-types.html#NMSecretAgentGetSecretsFlags)
#[repr(u32)]
pub enum GetSecretsFlags {
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

/// A data type used by Network-Manager to model its configuration.
///
/// In combination with the contained [PropMap] it allows modelling `<section>.<setting> = <value>`.
pub type NestedSettingsMap = HashMap<String, PropMap>;

/// The struct which corresponds to the D-Bus object on which methods are called
#[derive(Debug, Clone, Eq, PartialEq)]
struct ServerObj {
    known_nm_names: Vec<String>,
    mapping: AgentConfig,
}

pub fn run(mapping: AgentConfig) -> anyhow::Result<()> {
    let mut cross = Crossroads::new();

    tracing::debug!("Connecting to system bus");
    let conn = Connection::new_system().context("Could not connect to the system D-Bus daemon")?;
    tracing::debug!("Connected to bus as {}", conn.unique_name());

    let known_nm_names = get_nm_names(&conn)?;

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
            move |dbus: &mut DbusContext,
                  obj: &mut ServerObj,
                  (connection, _path, setting_name, hints, flags): (NestedSettingsMap, Path, String, Vec<String>, u32)| {
                tracing::debug!("got getSecrets() call");
                verify_access(dbus, &obj.known_nm_names)?;
                match mapping::get_secret(&mut obj.mapping, (&connection, &setting_name, &hints, flags)) {
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
                  _obj: &mut ServerObj,
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
                  _obj: &mut ServerObj,
                  (_connection, connection_path): (NestedSettingsMap, Path)| {
                tracing::warn!(%connection_path, "got SaveSecrets() call but this agent cannot save new secrets");
                Ok(())
            },
        );

        // DeleteSecrets()
        b.method(
            "DeleteSecrets",
            ("connection", "connection_path"),
            (),
            move |_ctx: &mut DbusContext,
                  _obj: &mut ServerObj,
                  (_connection, connection_path): (NestedSettingsMap, Path)| {
                tracing::warn!(%connection_path, "got DeleteSecrets() call but this agent cannot delete secrets");
                Ok(())
            },
        );
    });

    register_agent(&conn)?;

    cross.insert(
        "/org/freedesktop/NetworkManager/SecretAgent",
        &[iface_token],
        ServerObj {
            known_nm_names,
            mapping,
        },
    );

    tracing::info!("Registered with NetworkManager; now serving D-Bus API");
    cross.serve(&conn).context("Could not run D-Bus service")?;

    unreachable!();
}

/// Register this process as a secret agent with Network-Manager
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

/// Query the given bus for names that Network-Manager uses on it
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
