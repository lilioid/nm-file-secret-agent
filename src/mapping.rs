use std::{fs::File, io::Read, path::Path};

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct MappingConfig {
    #[serde(rename = "entry")]
    entries: Vec<MappingEntry>,
}

#[derive(Debug, Deserialize)]
pub struct MappingEntry {
    match_id: Option<String>,
    match_uuid: Option<String>,
    match_type: Option<String>,
    match_iface: Option<String>,
    match_setting: Option<String>,
    key: String,
    file: String,
}

impl MappingConfig {
    pub fn from_file(path: &Path) -> Self {
        let mut buf = String::new();
        File::options()
            .read(true)
            .open(path)
            .expect("Could not open config file")
            .read_to_string(&mut buf)
            .expect("Could not read file content");
        let config: Self = toml::from_str(&buf).expect("Could not parse config file");
        config
    }

    pub fn get_secrets(
        &self,
        conn_id: &str,
        conn_uuid: &str,
        conn_type: &str,
        iface_name: &str,
        setting_name: &str,
    ) -> Vec<(String, String)> {
        self.entries
            .iter()
            .filter(|entry| {
                if entry.match_id.as_ref().is_some_and(|val| val != conn_id) {
                    return false;
                }

                if entry
                    .match_uuid
                    .as_ref()
                    .is_some_and(|val| val != conn_uuid)
                {
                    return false;
                }

                if entry
                    .match_type
                    .as_ref()
                    .is_some_and(|val| val != conn_type)
                {
                    return false;
                }

                if entry
                    .match_iface
                    .as_ref()
                    .is_some_and(|val| val != iface_name)
                {
                    return false;
                }

                if entry
                    .match_setting
                    .as_ref()
                    .is_some_and(|val| val != setting_name)
                {
                    return false;
                }

                return true;
            })
            .map(|entry| {
                tracing::debug!(?entry, "Found matching secret entry");

                let mut secret_value = String::new();
                File::options()
                    .read(true)
                    .open(&entry.file)
                    .expect("Could not open secret file")
                    .read_to_string(&mut secret_value)
                    .expect("Could not read file content to string");
                tracing::debug!("Successfully read secret from file {}", &entry.file);

                (entry.key.to_owned(), secret_value)
            })
            .collect()
    }
}
