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
    #[serde(default)]
    pub trim: bool,
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
        match self.trim {
            true => Ok(secret_value.trim().to_string()),
            false => Ok(secret_value),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn make_config() -> (NamedTempFile, NamedTempFile) {
        let mut secret_file = NamedTempFile::with_suffix(".txt").expect("Could not create tempfile for storing a secret");
        let mut config_file = NamedTempFile::with_suffix(".toml").expect("Could not create tempfile");

        secret_file.write_all("foobar123\n".as_bytes()).expect("Could not write test secret to tempfile");
        config_file.write_all(format!(r#"
                [[entry]]
                match_id = "10"
                match_uuid = "11"
                match_type = "12"
                match_iface = "13"
                match_setting = "14"
                key = "foo"
                file = "{0}"

                [[entry]]
                match_id = "20"
                match_uuid = "21"
                match_type = "22"
                match_iface = "23"
                match_setting = "24"
                key = "foo"
                file = "{0}"
                trim = true
            "#, secret_file.path().display()).as_bytes()).expect("Could not write test config to tempfile");

        (secret_file, config_file)
    }
    
    #[test]
    fn test_config_parsing() {
        let ( _secret_file, config_file ) = make_config();
        let cfg = AgentConfig::from_file(config_file.path());
        assert!(cfg.is_ok());
    }

    #[test]
    fn test_config_validation() {
        let ( _secret_file, config_file ) = make_config();
        let cfg = AgentConfig::from_file(config_file.path()).unwrap();
        assert!(cfg.validate().is_ok())
    }
    
    /// if all properties of an entry match, it should be returned
    #[test]
    fn test_full_entry_matching() {
        let ( secret_file, config_file ) = make_config();
        let cfg = AgentConfig::from_file(config_file.path()).unwrap();
        let entry = cfg.find_matching_secrets("10", "11", "12", Some("13"), "14");
        assert_eq!(entry, vec![MappingEntry {
            match_id: Some("10".to_string()),
            match_uuid: Some("11".to_string()),
            match_type: Some("12".to_string()),
            match_iface: Some("13".to_string()),
            match_setting: Some("14".to_string()),
            key: "foo".to_string(),
            file: secret_file.path().display().to_string(),
            trim: false,
        }])
    }

    /// if an entry does not match with all its properties, it should not be returned
    #[test]
    fn test_partial_entry_matching() {
        let ( _secret_file, config_file ) = make_config();
        let cfg = AgentConfig::from_file(config_file.path()).unwrap();
        let entry = cfg.find_matching_secrets("10", "11", "12", Some("13"), "00");
        assert_eq!(entry, vec![])
    }

    /// if network-manager does not know an interface name yet but a user requested that interface names should be matched,
    /// the entry should not be returned
    #[test]
    fn test_missing_iface_name_entry_matching() {
        let ( _secret_file, config_file ) = make_config();
        let cfg = AgentConfig::from_file(config_file.path()).unwrap();
        let entry = cfg.find_matching_secrets("10", "11", "12", None, "14");
        assert_eq!(entry, vec![])
    }

    #[test]
    fn test_get_value_no_trim() {
        let ( _secret_file, config_file ) = make_config();
        let cfg = AgentConfig::from_file(config_file.path()).unwrap();
        let entry = &cfg.find_matching_secrets("10", "11", "12", Some("13"), "14")[0];
        let value = entry.read().unwrap();
        assert_eq!(value, "foobar123\n");
    }
    
    #[test]
    fn test_get_value_with_trim() {
        let ( _secret_file, config_file ) = make_config();
        let cfg = AgentConfig::from_file(config_file.path()).unwrap();
        let entry = &cfg.find_matching_secrets("20", "21", "22", Some("23"), "24")[0];
        let value = entry.read().unwrap();
        assert_eq!(value, "foobar123");
    }
}
