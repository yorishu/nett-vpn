use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Default)]
pub enum Mode {
    ViaVpn,
    #[default]
    Direct,
}

#[derive(Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(default)]
pub struct Rules {
    pub enabled: bool,
    pub mode: Mode,
    pub entries: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub config: String,
    #[serde(default)]
    pub sites: Rules,
    #[serde(default)]
    pub apps: Rules,
}
impl Profile {
    pub fn split(&self) -> bool {
        self.sites.enabled || self.apps.enabled
    }
    pub fn path(&self) -> Result<PathBuf, String> {
        Ok(super::storage::root()?.join(format!("{}.conf", self.id)))
    }
    pub fn stage(&self) -> Result<PathBuf, String> {
        let path = self.path()?;
        if std::fs::read_to_string(&path).ok().as_deref() != Some(&self.config) {
            std::fs::write(&path, &self.config).map_err(|e| e.to_string())?;
        }
        super::detect_config(&path)?;
        Ok(path)
    }
    pub fn protocol(&self) -> super::Protocol {
        if self.config.lines().any(|l| {
            l.split_once('=').is_some_and(|(k, _)| {
                [
                    "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1",
                    "i2", "i3", "i4", "i5",
                ]
                .contains(&k.trim().to_ascii_lowercase().as_str())
            })
        }) {
            super::Protocol::AmneziaWg
        } else {
            super::Protocol::WireGuard
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Library {
    pub profiles: Vec<Profile>,
    pub selected: Option<String>,
    pub effects: bool,
    pub motion: bool,
    pub kill_switch: bool,
}
impl Default for Library {
    fn default() -> Self {
        Self {
            profiles: Vec::new(),
            selected: None,
            effects: true,
            motion: true,
            kill_switch: false,
        }
    }
}
impl Library {
    pub fn selected(&self) -> Option<&Profile> {
        self.profiles
            .iter()
            .find(|p| Some(&p.id) == self.selected.as_ref())
    }
    pub fn selected_mut(&mut self) -> Option<&mut Profile> {
        self.profiles
            .iter_mut()
            .find(|p| Some(&p.id) == self.selected.as_ref())
    }
    pub fn import(&mut self, path: &Path) -> Result<(), String> {
        super::detect_config(path)?;
        let id = format!(
            "n{:012x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_nanos()
                & 0xffffffffffff
        );
        self.profiles.push(Profile {
            id: id.clone(),
            name: path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .chars()
                .take(64)
                .collect(),
            config: std::fs::read_to_string(path).map_err(|e| e.to_string())?,
            sites: Rules::default(),
            apps: Rules::default(),
        });
        self.selected = Some(id);
        Ok(())
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.profiles.len() > 100 {
            return Err("MAXIMUM 100 PROFILES".into());
        }
        let mut ids = std::collections::HashSet::new();
        for p in &self.profiles {
            if p.id.is_empty()
                || p.id.len() > 15
                || !p
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_=+.-".contains(&b))
                || p.id.contains("..")
                || !ids.insert(&p.id)
            {
                return Err("INVALID OR DUPLICATE PROFILE ID".into());
            }
            if p.name.trim().is_empty()
                || p.name.chars().count() > 64
                || p.name.chars().any(char::is_control)
            {
                return Err("PROFILE NAME MUST HAVE 1-64 CHARACTERS".into());
            }
            if p.config.len() > 1024 * 1024 {
                return Err("PROFILE TOO LARGE".into());
            }
            super::split::validate_rules(&p.sites, false)?;
            super::split::validate_rules(&p.apps, true)?;
        }
        if self.selected.is_some() && self.selected().is_none() {
            return Err("SELECTED PROFILE NOT FOUND".into());
        }
        Ok(())
    }
    pub fn save(&self) -> Result<(), String> {
        self.save_at(&super::storage::root()?)
    }
    fn save_at(&self, root: &Path) -> Result<(), String> {
        self.validate()?;
        super::storage::secure_directory(root)?;
        let data = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        let encrypted = super::storage::crypt(&data, true)?;
        std::fs::write(root.join("profiles.new"), encrypted).map_err(|e| e.to_string())?;
        std::fs::rename(root.join("profiles.new"), root.join("profiles.dpapi"))
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    pub fn load() -> Result<Self, String> {
        let root = super::storage::root()?;
        match std::fs::read(root.join("profiles.dpapi")) {
            Ok(data) => {
                let result: Self = serde_json::from_slice(&super::storage::crypt(&data, false)?)
                    .map_err(|e| e.to_string())?;
                result.validate()?;
                super::storage::secure_directory(&root)?;
                Ok(result)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut library = Self::default();
                if let Some(path) = super::storage::load()? {
                    library.import(&path)?;
                    // Keep the old tunnel name so an already running legacy service is found.
                    let old_id = super::tunnel_name(&path);
                    library.profiles[0].id = old_id.clone();
                    library.selected = Some(old_id);
                    library.save()?;
                }
                Ok(library)
            }
            Err(e) => Err(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn encrypted_library_updates_atomically_without_losing_other_profiles() {
        let root = std::env::temp_dir().join(format!("nett-profiles-test-{}", std::process::id()));
        let mut library = super::Library::default();
        for (id, name) in [("home", "home"), ("work", "work")] {
            library.profiles.push(super::Profile {
                id: id.into(),
                name: name.into(),
                config: format!("PrivateKey={id}-secret"),
                sites: Default::default(),
                apps: Default::default(),
            });
        }
        library.selected = Some("home".into());
        library.save_at(&root).unwrap();
        library.selected = Some("work".into());
        library.save_at(&root).unwrap();
        let encrypted = std::fs::read(root.join("profiles.dpapi")).unwrap();
        assert!(!encrypted.windows(10).any(|s| s == b"PrivateKey"));
        let restored: super::Library =
            serde_json::from_slice(&crate::storage::crypt(&encrypted, false).unwrap()).unwrap();
        assert_eq!(restored.profiles.len(), 2);
        assert_eq!(restored.selected().unwrap().name, "work");
        assert_eq!(restored.profiles[0].config, "PrivateKey=home-secret");
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn selection_and_metadata_survive_serialization() {
        let mut library = super::Library::default();
        library.kill_switch = true;
        library.profiles.push(super::Profile {
            id: "n123".into(),
            name: "home".into(),
            config: "secret".into(),
            sites: Default::default(),
            apps: Default::default(),
        });
        library.selected = Some("n123".into());
        let copy: super::Library =
            serde_json::from_slice(&serde_json::to_vec(&library).unwrap()).unwrap();
        copy.validate().unwrap();
        assert_eq!(copy.selected().unwrap().name, "home");
        assert_eq!(copy.selected().unwrap().config, "secret");
        assert!(copy.kill_switch);
        let legacy: super::Library = serde_json::from_str("{}").unwrap();
        assert!(!legacy.kill_switch);
        library.profiles[0].id = "../escape".into();
        assert!(library.validate().is_err());
    }

    #[test]
    fn routing_lists_can_be_saved_even_when_engine_rejects_config() {
        let root = std::env::temp_dir().join(format!("nett-rule-save-test-{}", std::process::id()));
        let mut library = super::Library::default();
        library.profiles.push(super::Profile {
            id: "test".into(),
            name: "home".into(),
            config: "[Interface]\nJc=4\nDisableCookies=invalid".into(),
            sites: super::Rules {
                enabled: true,
                mode: super::Mode::Direct,
                entries: vec!["example.com".into(), "192.168.10.0/24".into()],
            },
            apps: super::Rules {
                enabled: true,
                mode: super::Mode::Direct,
                entries: vec![r"C:\Apps\ShairportQt.exe".into()],
            },
        });
        library.selected = Some("test".into());
        assert!(crate::split::configuration(library.selected().unwrap()).is_err());
        library.save_at(&root).unwrap();
        let bytes = std::fs::read(root.join("profiles.dpapi")).unwrap();
        let restored: super::Library =
            serde_json::from_slice(&crate::storage::crypt(&bytes, false).unwrap()).unwrap();
        assert!(restored == library);
        assert_eq!(restored.selected().unwrap().sites.entries.len(), 2);
        assert_eq!(restored.selected().unwrap().apps.entries.len(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }
}
