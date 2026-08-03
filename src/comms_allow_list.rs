//! Persistence for the comms allow list.
//!
//! The YAML named by `comms.allow_list` seeds the list on first boot. Once a
//! rule has been set through the API the persisted snapshot supersedes it, so
//! runtime changes survive a restart. The storage key is present exactly when
//! the API has been used, so its presence is what decides which source wins.

use std::{
    net::IpAddr,
    rc::Rc,
    sync::{Arc, Mutex},
};

use bitvmx_broker::identification::{allow_list::AllowList, identifier::PubkHash};
use serde::{Deserialize, Serialize};
use storage_backend::storage::{KeyValueStore, Storage};
use tracing::info;

use crate::errors::BitVMXError;

const STORAGE_KEY: &str = "comms/allow_list";

/// Snapshot of the comms allow list as configured through the API.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PersistedAllowList {
    /// `None` as the address means the entry matches any source IP.
    pub entries: Vec<(PubkHash, Option<IpAddr>)>,
    pub allow_all: bool,
}

/// The persisted list, or `None` if the API has never been used and the YAML
/// still governs.
fn load(store: &Rc<Storage>) -> Result<Option<PersistedAllowList>, BitVMXError> {
    Ok(store.get(STORAGE_KEY, None)?)
}

/// Snapshot the live allow list and write it through.
pub fn save(store: &Rc<Storage>, allow_list: &AllowList) -> Result<(), BitVMXError> {
    let persisted = PersistedAllowList {
        entries: allow_list.entries(),
        allow_all: allow_list.is_allow_all(),
    };
    store.set(STORAGE_KEY, persisted, None)?;
    Ok(())
}

/// Build the comms allow list, preferring the persisted one over `yaml_path`.
pub fn build(
    store: &Rc<Storage>,
    yaml_path: &str,
) -> Result<Arc<Mutex<AllowList>>, BitVMXError> {
    let Some(persisted) = load(store)? else {
        return Ok(AllowList::from_file(yaml_path)?);
    };

    info!(
        "Using persisted comms allow list: {} entries, allow_all={}",
        persisted.entries.len(),
        persisted.allow_all
    );

    let allow_list = AllowList::new();
    {
        let mut guard = allow_list
            .lock()
            .map_err(|e| BitVMXError::PoisonedLockError(e.to_string()))?;
        for (hash, addr) in persisted.entries {
            guard.add_entry(hash, addr);
        }
        guard.set_allow_all(persisted.allow_all);
    }
    Ok(allow_list)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestStorageDir;

    fn test_storage_dir() -> TestStorageDir {
        TestStorageDir::new("bitvmx-comms-allow-list-test")
    }

    /// A YAML allow list naming a single wildcard entry, written inside `dir`
    /// so it is cleaned up along with the storage.
    fn yaml_with(dir: &TestStorageDir, entry: &str) -> String {
        std::fs::create_dir_all(dir.path()).unwrap();
        let path = format!("{}/allow_list.yaml", dir.path());
        std::fs::write(&path, format!("{entry}: ~\n")).unwrap();
        path
    }

    /// The blanket-accept YAML that every deployment currently ships. Takes
    /// the `content == "allow_all"` short-circuit in `AllowList::from_file`,
    /// not the entry-map path `yaml_with` produces.
    fn allow_all_yaml(dir: &TestStorageDir) -> String {
        std::fs::create_dir_all(dir.path()).unwrap();
        let path = format!("{}/allow_list.yaml", dir.path());
        std::fs::write(&path, "allow_all").unwrap();
        path
    }

    fn addr(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn load_returns_none_before_the_api_is_used() {
        let dir = test_storage_dir();
        let store = dir.storage();
        assert_eq!(load(&store).unwrap(), None);
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = test_storage_dir();
        let store = dir.storage();
        let allow_list = AllowList::new();
        {
            let mut guard = allow_list.lock().unwrap();
            guard.add_entry("pinned".to_string(), Some(addr("127.0.0.1")));
            guard.add_entry("wildcard".to_string(), None);
            save(&store, &guard).unwrap();
        }

        let mut loaded = load(&store).unwrap().expect("persisted list");
        loaded.entries.sort();
        assert_eq!(
            loaded.entries,
            vec![
                ("pinned".to_string(), Some(addr("127.0.0.1"))),
                ("wildcard".to_string(), None),
            ]
        );
        assert!(!loaded.allow_all);
    }

    #[test]
    fn allow_all_survives_the_round_trip() {
        let dir = test_storage_dir();
        let store = dir.storage();
        let allow_list = AllowList::new();
        {
            let mut guard = allow_list.lock().unwrap();
            guard.set_allow_all(true);
            save(&store, &guard).unwrap();
        }
        assert!(load(&store).unwrap().unwrap().allow_all);
    }

    #[test]
    fn build_ignores_the_yaml_once_a_list_is_persisted() {
        let dir = test_storage_dir();
        let store = dir.storage();
        let yaml = yaml_with(&dir, "from-yaml");

        // the API removed "from-yaml" and added "from-api"
        store
            .set(
                STORAGE_KEY,
                PersistedAllowList {
                    entries: vec![("from-api".to_string(), None)],
                    allow_all: false,
                },
                None,
            )
            .unwrap();

        let allow_list = build(&store, &yaml).unwrap();
        let guard = allow_list.lock().unwrap();

        assert!(guard.is_allowed(&"from-api".to_string(), addr("127.0.0.1")));
        assert!(
            !guard.is_allowed(&"from-yaml".to_string(), addr("127.0.0.1")),
            "a removed entry must not come back from the YAML on restart",
        );
    }

    #[test]
    fn build_falls_back_to_the_yaml_when_nothing_is_persisted() {
        let dir = test_storage_dir();
        let store = dir.storage();
        let yaml = yaml_with(&dir, "from-yaml");

        let allow_list = build(&store, &yaml).unwrap();
        assert!(allow_list
            .lock()
            .unwrap()
            .is_allowed(&"from-yaml".to_string(), addr("127.0.0.1")));
    }

    /// The deployment case: the shipped YAML says `allow_all`, the operator
    /// has since locked down through the API. A restart must not reopen it.
    #[test]
    fn build_keeps_allow_all_disabled_against_an_allow_all_yaml() {
        let dir = test_storage_dir();
        let store = dir.storage();
        let yaml = allow_all_yaml(&dir);

        // the YAML on its own accepts everyone
        assert!(AllowList::from_file(&yaml)
            .unwrap()
            .lock()
            .unwrap()
            .is_allow_all());

        store
            .set(
                STORAGE_KEY,
                PersistedAllowList {
                    entries: vec![("known-peer".to_string(), None)],
                    allow_all: false,
                },
                None,
            )
            .unwrap();

        let allow_list = build(&store, &yaml).unwrap();
        let guard = allow_list.lock().unwrap();

        assert!(!guard.is_allow_all(), "the YAML must not reopen blanket mode");
        assert!(guard.is_allowed(&"known-peer".to_string(), addr("127.0.0.1")));
        assert!(
            !guard.is_allowed(&"stranger".to_string(), addr("127.0.0.1")),
            "an unlisted peer must stay rejected across a restart",
        );
    }

    #[test]
    fn build_restores_the_allow_all_flag() {
        let dir = test_storage_dir();
        let store = dir.storage();
        let yaml = yaml_with(&dir, "from-yaml");

        store
            .set(
                STORAGE_KEY,
                PersistedAllowList {
                    entries: vec![],
                    allow_all: true,
                },
                None,
            )
            .unwrap();

        let allow_list = build(&store, &yaml).unwrap();
        assert!(allow_list.lock().unwrap().is_allow_all());
    }
}
