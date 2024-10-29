// This code was autogenerated with `dbus-codegen-rust -s -g -m None -d org.freedesktop.NetworkManager -p /org/freedesktop/NetworkManager/AgentManager`, see https://github.com/diwic/dbus-rs
use dbus;
#[allow(unused_imports)]
use dbus::arg;
use dbus::blocking;

pub trait OrgFreedesktopDBusProperties {
    fn get<R0: for<'b> arg::Get<'b> + 'static>(
        &self,
        interface_name: &str,
        property_name: &str,
    ) -> Result<R0, dbus::Error>;
    fn get_all(&self, interface_name: &str) -> Result<arg::PropMap, dbus::Error>;
    fn set<I2: arg::Arg + arg::Append>(
        &self,
        interface_name: &str,
        property_name: &str,
        value: I2,
    ) -> Result<(), dbus::Error>;
}

#[derive(Debug)]
pub struct OrgFreedesktopDBusPropertiesPropertiesChanged {
    pub interface_name: String,
    pub changed_properties: arg::PropMap,
    pub invalidated_properties: Vec<String>,
}

impl arg::AppendAll for OrgFreedesktopDBusPropertiesPropertiesChanged {
    fn append(&self, i: &mut arg::IterAppend) {
        arg::RefArg::append(&self.interface_name, i);
        arg::RefArg::append(&self.changed_properties, i);
        arg::RefArg::append(&self.invalidated_properties, i);
    }
}

impl arg::ReadAll for OrgFreedesktopDBusPropertiesPropertiesChanged {
    fn read(i: &mut arg::Iter) -> Result<Self, arg::TypeMismatchError> {
        Ok(OrgFreedesktopDBusPropertiesPropertiesChanged {
            interface_name: i.read()?,
            changed_properties: i.read()?,
            invalidated_properties: i.read()?,
        })
    }
}

impl dbus::message::SignalArgs for OrgFreedesktopDBusPropertiesPropertiesChanged {
    const NAME: &'static str = "PropertiesChanged";
    const INTERFACE: &'static str = "org.freedesktop.DBus.Properties";
}

impl<'a, T: blocking::BlockingSender, C: ::std::ops::Deref<Target = T>> OrgFreedesktopDBusProperties
    for blocking::Proxy<'a, C>
{
    fn get<R0: for<'b> arg::Get<'b> + 'static>(
        &self,
        interface_name: &str,
        property_name: &str,
    ) -> Result<R0, dbus::Error> {
        self.method_call(
            "org.freedesktop.DBus.Properties",
            "Get",
            (interface_name, property_name),
        )
        .and_then(|r: (arg::Variant<R0>,)| Ok((r.0).0))
    }

    fn get_all(&self, interface_name: &str) -> Result<arg::PropMap, dbus::Error> {
        self.method_call(
            "org.freedesktop.DBus.Properties",
            "GetAll",
            (interface_name,),
        )
        .and_then(|r: (arg::PropMap,)| Ok(r.0))
    }

    fn set<I2: arg::Arg + arg::Append>(
        &self,
        interface_name: &str,
        property_name: &str,
        value: I2,
    ) -> Result<(), dbus::Error> {
        self.method_call(
            "org.freedesktop.DBus.Properties",
            "Set",
            (interface_name, property_name, arg::Variant(value)),
        )
    }
}

pub trait OrgFreedesktopDBusIntrospectable {
    fn introspect(&self) -> Result<String, dbus::Error>;
}

impl<'a, T: blocking::BlockingSender, C: ::std::ops::Deref<Target = T>>
    OrgFreedesktopDBusIntrospectable for blocking::Proxy<'a, C>
{
    fn introspect(&self) -> Result<String, dbus::Error> {
        self.method_call("org.freedesktop.DBus.Introspectable", "Introspect", ())
            .and_then(|r: (String,)| Ok(r.0))
    }
}

pub trait OrgFreedesktopDBusPeer {
    fn ping(&self) -> Result<(), dbus::Error>;
    fn get_machine_id(&self) -> Result<String, dbus::Error>;
}

impl<'a, T: blocking::BlockingSender, C: ::std::ops::Deref<Target = T>> OrgFreedesktopDBusPeer
    for blocking::Proxy<'a, C>
{
    fn ping(&self) -> Result<(), dbus::Error> {
        self.method_call("org.freedesktop.DBus.Peer", "Ping", ())
    }

    fn get_machine_id(&self) -> Result<String, dbus::Error> {
        self.method_call("org.freedesktop.DBus.Peer", "GetMachineId", ())
            .and_then(|r: (String,)| Ok(r.0))
    }
}

pub trait OrgFreedesktopNetworkManagerAgentManager {
    fn register(&self, identifier: &str) -> Result<(), dbus::Error>;
    fn register_with_capabilities(
        &self,
        identifier: &str,
        capabilities: u32,
    ) -> Result<(), dbus::Error>;
    fn unregister(&self) -> Result<(), dbus::Error>;
}

impl<'a, T: blocking::BlockingSender, C: ::std::ops::Deref<Target = T>>
    OrgFreedesktopNetworkManagerAgentManager for blocking::Proxy<'a, C>
{
    fn register(&self, identifier: &str) -> Result<(), dbus::Error> {
        self.method_call(
            "org.freedesktop.NetworkManager.AgentManager",
            "Register",
            (identifier,),
        )
    }

    fn register_with_capabilities(
        &self,
        identifier: &str,
        capabilities: u32,
    ) -> Result<(), dbus::Error> {
        self.method_call(
            "org.freedesktop.NetworkManager.AgentManager",
            "RegisterWithCapabilities",
            (identifier, capabilities),
        )
    }

    fn unregister(&self) -> Result<(), dbus::Error> {
        self.method_call(
            "org.freedesktop.NetworkManager.AgentManager",
            "Unregister",
            (),
        )
    }
}
