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
}
impl Profile {
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

#[derive(Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct VpnConfig {
    pub profiles: Vec<Profile>,
    pub selected: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct UserConfig {
    pub sites: Rules,
    pub apps: Rules,
    pub effects: bool,
    pub motion: bool,
    pub kill_switch: bool,
}
impl Default for UserConfig {
    fn default() -> Self {
        Self {
            sites: Rules::default(),
            apps: Rules::default(),
            effects: true,
            motion: true,
            kill_switch: false,
        }
    }
}

impl UserConfig {
    pub fn split(&self) -> bool {
        self.sites.enabled || self.apps.enabled
    }
    pub fn validate(&self) -> Result<(), String> {
        super::split::validate_rules(&self.sites, false)?;
        super::split::validate_rules(&self.apps, true)
    }
    pub fn save(&self) -> Result<(), String> {
        self.save_at(&super::storage::root()?)
    }
    fn save_at(&self, root: &Path) -> Result<(), String> {
        self.validate()?;
        super::storage::secure_directory(root)?;
        save_encrypted(&root.join("user-config.dpapi"), self)
    }
}

#[derive(Clone, Default, PartialEq)]
pub struct Library {
    pub vpn: VpnConfig,
    pub user: UserConfig,
}

impl Library {
    pub fn selected(&self) -> Option<&Profile> {
        self.vpn
            .profiles
            .iter()
            .find(|p| Some(&p.id) == self.vpn.selected.as_ref())
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
        self.vpn.profiles.push(Profile {
            id: id.clone(),
            name: path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .chars()
                .take(64)
                .collect(),
            config: std::fs::read_to_string(path).map_err(|e| e.to_string())?,
        });
        self.vpn.selected = Some(id);
        Ok(())
    }
    pub fn validate(&self) -> Result<(), String> {
        self.user.validate()?;
        if self.vpn.profiles.len() > 100 {
            return Err("MAXIMUM 100 PROFILES".into());
        }
        let mut ids = std::collections::HashSet::new();
        for p in &self.vpn.profiles {
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
        }
        if self.vpn.selected.is_some() && self.selected().is_none() {
            return Err("SELECTED PROFILE NOT FOUND".into());
        }
        Ok(())
    }
    pub fn save_vpn(&self) -> Result<(), String> {
        self.validate()?;
        let root = super::storage::root()?;
        super::storage::secure_directory(&root)?;
        save_encrypted(&root.join("profiles.dpapi"), &self.vpn)
    }
    fn save_at(&self, root: &Path) -> Result<(), String> {
        self.validate()?;
        super::storage::secure_directory(root)?;
        save_encrypted(&root.join("user-config.dpapi"), &self.user)?;
        save_encrypted(&root.join("profiles.dpapi"), &self.vpn)?;
        Ok(())
    }
    pub fn load() -> Result<Self, String> {
        let root = super::storage::root()?;
        let mut library = Self::load_at(&root)?;
        if !root.join("profiles.dpapi").exists()
            && let Some(path) = super::storage::load()?
        {
            library.import(&path)?;
            // Keep the old tunnel name so an already running legacy service is found.
            let old_id = super::tunnel_name(&path);
            library.vpn.profiles[0].id = old_id.clone();
            library.vpn.selected = Some(old_id);
            library.save_vpn()?;
        }
        Ok(library)
    }

    fn load_at(root: &Path) -> Result<Self, String> {
        let user_path = root.join("user-config.dpapi");
        let mut user = match std::fs::read(&user_path) {
            Ok(data) => Some(
                serde_json::from_slice::<UserConfig>(&super::storage::crypt(&data, false)?)
                    .map_err(|e| e.to_string())?,
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.to_string()),
        };
        match std::fs::read(root.join("profiles.dpapi")) {
            Ok(data) => {
                let value: serde_json::Value =
                    serde_json::from_slice(&super::storage::crypt(&data, false)?)
                        .map_err(|e| e.to_string())?;
                let vpn: VpnConfig =
                    serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
                let legacy = value.get("effects").is_some()
                    || value.get("motion").is_some()
                    || value.get("kill_switch").is_some()
                    || value["profiles"].as_array().is_some_and(|profiles| {
                        profiles
                            .iter()
                            .any(|p| p.get("sites").is_some() || p.get("apps").is_some())
                    });
                if user.is_none() && legacy {
                    let mut migrated: UserConfig =
                        serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
                    let profiles = value["profiles"]
                        .as_array()
                        .ok_or("INVALID PROFILE LIBRARY")?;
                    if let Some(selected) = profiles
                        .iter()
                        .find(|p| p["id"].as_str() == vpn.selected.as_deref())
                        .or_else(|| profiles.first())
                    {
                        if let Some(sites) = selected.get("sites") {
                            migrated.sites =
                                serde_json::from_value(sites.clone()).map_err(|e| e.to_string())?;
                        }
                        if let Some(apps) = selected.get("apps") {
                            migrated.apps =
                                serde_json::from_value(apps.clone()).map_err(|e| e.to_string())?;
                        }
                    }
                    user = Some(migrated);
                }
                let result = Self {
                    vpn,
                    user: user.unwrap_or_default(),
                };
                result.validate()?;
                super::storage::secure_directory(root)?;
                if legacy {
                    // Preserve every old profile's rules and keys before separating the stores.
                    use std::io::Write;
                    match std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(root.join("profiles.before-user-config.dpapi"))
                    {
                        Ok(mut backup) => {
                            backup.write_all(&data).map_err(|e| e.to_string())?;
                            backup.sync_all().map_err(|e| e.to_string())?;
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                            if std::fs::read(root.join("profiles.before-user-config.dpapi"))
                                .map_err(|e| e.to_string())?
                                != data
                            {
                                return Err(
                                    "LEGACY BACKUP DIFFERS - ORIGINAL VAULT RETAINED".into()
                                );
                            }
                        }
                        Err(e) => return Err(e.to_string()),
                    }
                    result.save_at(root)?;
                }
                Ok(result)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let result = Self {
                    vpn: VpnConfig::default(),
                    user: user.unwrap_or_default(),
                };
                result.validate()?;
                if user_path.exists() {
                    super::storage::secure_directory(root)?;
                }
                Ok(result)
            }
            Err(e) => Err(e.to_string()),
        }
    }
}

fn save_encrypted(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let data = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    match std::fs::read(path) {
        Ok(existing) => {
            if super::storage::crypt(&existing, false)? == data {
                return Ok(());
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.to_string()),
    }
    let temporary = path.with_extension("new");
    std::fs::write(&temporary, super::storage::crypt(&data, true)?).map_err(|e| e.to_string())?;
    std::fs::rename(&temporary, path).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("nett-user-config-{name}-{}", std::process::id()))
    }
    fn profile(id: &str) -> Profile {
        Profile { id:id.into(),name:id.into(),config:"[Interface]\nPrivateKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress=10.0.0.2/32\n[Peer]\nPublicKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nEndpoint=127.0.0.1:51820\nAllowedIPs=0.0.0.0/0".into() }
    }
    fn library() -> Library {
        let mut library = Library::default();
        library.vpn.profiles = vec![profile("home"), profile("work")];
        library.vpn.selected = Some("home".into());
        library.user.sites = Rules {
            enabled: true,
            mode: Mode::Direct,
            entries: vec!["example.com".into()],
        };
        library.user.apps = Rules {
            enabled: true,
            mode: Mode::Direct,
            entries: vec![r"C:\Apps\Discord.exe".into()],
        };
        library
    }
    fn write_legacy(root: &Path) -> Vec<u8> {
        crate::storage::secure_directory(root).unwrap();
        let mut value = serde_json::to_value(library().vpn).unwrap();
        value["effects"] = serde_json::json!(false);
        value["motion"] = serde_json::json!(true);
        value["kill_switch"] = serde_json::json!(true);
        value["selected"] = serde_json::json!("work");
        value["profiles"][0]["sites"] =
            serde_json::json!({"enabled":true,"mode":"Direct","entries":["old.example"]});
        value["profiles"][1]["sites"] =
            serde_json::json!({"enabled":true,"mode":"ViaVpn","entries":["selected.example"]});
        value["profiles"][1]["apps"] =
            serde_json::json!({"enabled":true,"mode":"Direct","entries":[r"C:\Apps\Discord.exe"]});
        let bytes = crate::storage::crypt(&serde_json::to_vec(&value).unwrap(), true).unwrap();
        std::fs::write(root.join("profiles.dpapi"), &bytes).unwrap();
        bytes
    }
    #[test]
    fn separate_encrypted_stores_do_not_rewrite_each_other() {
        let root = root("separate");
        let mut library = library();
        library.save_at(&root).unwrap();
        let vpn = std::fs::read(root.join("profiles.dpapi")).unwrap();
        assert!(!vpn.windows(10).any(|w| w == b"PrivateKey"));
        let value: serde_json::Value =
            serde_json::from_slice(&crate::storage::crypt(&vpn, false).unwrap()).unwrap();
        assert!(value.get("sites").is_none() && value["profiles"][0].get("sites").is_none());
        library.user.sites.entries.push("second.example".into());
        library.user.kill_switch = true;
        library.save_at(&root).unwrap();
        assert_eq!(std::fs::read(root.join("profiles.dpapi")).unwrap(), vpn);
        let user = std::fs::read(root.join("user-config.dpapi")).unwrap();
        library.vpn.selected = Some("work".into());
        library.vpn.profiles[1].name = "renamed".into();
        library.save_at(&root).unwrap();
        assert_eq!(std::fs::read(root.join("user-config.dpapi")).unwrap(), user);
        assert!(Library::load_at(&root).unwrap() == library);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn user_rules_survive_import_and_removing_all_vpn_profiles() {
        let root = root("vpn-changes");
        let mut library = library();
        library.save_at(&root).unwrap();
        let user = library.user.clone();
        let bytes = std::fs::read(root.join("user-config.dpapi")).unwrap();
        let conf = root.join("new.conf");
        std::fs::write(&conf, &profile("fake").config).unwrap();
        library.import(&conf).unwrap();
        assert!(library.user == user);
        library.vpn.profiles.clear();
        library.vpn.selected = None;
        library.save_at(&root).unwrap();
        assert!(Library::load_at(&root).unwrap().user == user);
        assert_eq!(
            std::fs::read(root.join("user-config.dpapi")).unwrap(),
            bytes
        );
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn user_config_saves_without_a_vpn_and_invalid_rules_do_not_replace_it() {
        let root = root("user-only");
        let user = library().user;
        user.save_at(&root).unwrap();
        assert!(!root.join("profiles.dpapi").exists());
        let loaded = Library::load_at(&root).unwrap();
        assert!(loaded.vpn.profiles.is_empty() && loaded.user == user);
        let mut invalid = user;
        invalid.sites.entries.push("https://invalid.example".into());
        assert!(invalid.save_at(&root).is_err());
        assert!(Library::load_at(&root).unwrap().user == loaded.user);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn migration_uses_selected_profile_and_keeps_all_legacy_data_in_encrypted_backup() {
        let root = root("migration");
        let original = write_legacy(&root);
        let migrated = Library::load_at(&root).unwrap();
        assert_eq!(migrated.user.sites.entries, vec!["selected.example"]);
        assert!(migrated.user.sites.mode == Mode::ViaVpn);
        assert!(!migrated.user.effects && migrated.user.motion && migrated.user.kill_switch);
        assert_eq!(migrated.user.apps.entries, vec![r"C:\Apps\Discord.exe"]);
        assert_eq!(migrated.vpn.profiles.len(), 2);
        assert_eq!(migrated.vpn.selected.as_deref(), Some("work"));
        assert_eq!(
            std::fs::read(root.join("profiles.before-user-config.dpapi")).unwrap(),
            original
        );
        let mut user = migrated.user;
        user.sites.entries = vec!["edited.example".into()];
        user.save_at(&root).unwrap();
        assert!(Library::load_at(&root).unwrap().user == user);
        assert_eq!(
            std::fs::read(root.join("profiles.before-user-config.dpapi")).unwrap(),
            original
        );
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn existing_user_config_wins_over_legacy_rules() {
        let root = root("existing-user");
        write_legacy(&root);
        let user = library().user;
        user.save_at(&root).unwrap();
        let bytes = std::fs::read(root.join("user-config.dpapi")).unwrap();
        assert!(Library::load_at(&root).unwrap().user == user);
        assert_eq!(
            std::fs::read(root.join("user-config.dpapi")).unwrap(),
            bytes
        );
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn failed_backup_preserves_original_vault() {
        let root = root("backup-failure");
        let original = write_legacy(&root);
        std::fs::write(
            root.join("profiles.before-user-config.dpapi"),
            b"incomplete backup",
        )
        .unwrap();
        assert!(Library::load_at(&root).is_err());
        assert_eq!(
            std::fs::read(root.join("profiles.dpapi")).unwrap(),
            original
        );
        assert!(!root.join("user-config.dpapi").exists());
        std::fs::remove_dir_all(root).unwrap();
    }
}
