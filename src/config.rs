//! Configuration file related functionality
use std::{fs::File, io::Read, path::Path};

use anyhow::Context;
use serde::Deserialize;
use uuid::Uuid;

/// A configurable mapping describing match rules for Network-Manager requests and the files with which those requests should be answered
#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
pub struct AgentConfig {
    #[serde(rename = "entry")]
    pub entries: Vec<MappingEntry>,
}

impl AgentConfig {
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
                if Uuid::parse_str(match_uuid).is_err() {
                    tracing::warn!("match_uuid value {match_uuid} of config entry {i} is not a valid uuid and will prevent the entry from matching anything");
                }
            }
        }
        Ok(())
    }

    /// Find secret entries from the configuration that match the given input
    pub fn find_matching_secrets(
        &self,
        conn_id: &str,
        conn_uuid: &str,
        conn_type: &str,
        iface_name: Option<&str>,
        setting_name: &str,
    ) -> Vec<MappingEntry> {
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

                true
            })
            .cloned()
            .collect()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
pub struct MappingEntry {
    pub match_id: Option<String>,
    pub match_uuid: Option<String>,
    pub match_type: Option<String>,
    pub match_iface: Option<String>,
    pub match_setting: Option<String>,
    pub key: String,
    pub file: String,
}

impl MappingEntry {
    /// Read the secret content from the backing file
    pub fn read(&self) -> anyhow::Result<String> {
        tracing::trace!(file = self.file, "Reading secret from file");

        let mut secret_value = String::new();
        File::options()
            .read(true)
            .open(&self.file)
            .with_context(|| format!("Could not open secret file at {}", &self.file))?
            .read_to_string(&mut secret_value)
            .with_context(|| format!("Could not read content of file at {}", &self.file))?;

        tracing::trace!("Successfully read secret from file {}", &self.file);
        Ok(secret_value)
    }
}
