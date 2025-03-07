use std::{fs::File, io::Read, path::Path};

use anyhow::{Context, Result};
use serde::Deserialize;
use uuid::Uuid;

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
    /// Read a mapping configuration from the file located at `path`
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let mut buf = String::new();
        File::options()
            .read(true)
            .open(path)
            .context("Could not open config file")?
            .read_to_string(&mut buf)
            .context("Could not read file content")?;
        let config: Self = toml::from_str(&buf)
            .context("Could not parse config file as required TOML data-structure")?;
        Ok(config)
    }

    /// Validate that all configured secrets can be read and warn about possibly invalid match settings
    pub fn validate(&self) -> anyhow::Result<()> {
        for (i, entry) in self.entries.iter().enumerate() {
            // try to open the file
            File::options()
                .read(true)
                .open(&entry.file)
                .with_context(|| {
                    format!("Could not open file backing secret at {}", &entry.file)
                })?;

            // emit warning if match_uuid does not look like a uuid
            if let Some(match_uuid) = &entry.match_uuid {
                if let Err(_) = Uuid::parse_str(&match_uuid) {
                    tracing::warn!("match_uuid value {match_uuid} of config entry {i} is not a valid uuid and will prevent the entry from matching anything");
                }
            }
        }
        Ok(())
    }

    pub fn get_secrets(
        &self,
        conn_id: &str,
        conn_uuid: &str,
        conn_type: &str,
        iface_name: Option<&str>,
        setting_name: &str,
    ) -> anyhow::Result<Vec<(String, String)>> {
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

                if let Some(iface_name) = iface_name {
                    if entry
                        .match_iface
                        .as_ref()
                        .is_some_and(|val| val != iface_name)
                    {
                        return false;
                    }
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
                tracing::info!(?entry, "Found matching secret entry");

                let mut secret_value = String::new();
                File::options()
                    .read(true)
                    .open(&entry.file)
                    .with_context(|| format!("Could not open secret file at {}", &entry.file))?
                    .read_to_string(&mut secret_value)
                    .with_context(|| {
                        format!("Could not read file content from secret at {}", &entry.file)
                    })?;
                tracing::debug!("Successfully read secret from file {}", &entry.file);

                Ok((entry.key.to_owned(), secret_value))
            })
            .collect::<Result<Vec<_>>>()
    }
}
