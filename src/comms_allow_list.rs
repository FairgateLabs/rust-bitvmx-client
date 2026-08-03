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
use tracing::{info, warn};

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

/// The entries and blanket flag, for a list request.
pub fn snapshot(
    allow_list: &Arc<Mutex<AllowList>>,
) -> Result<(Vec<(PubkHash, Option<IpAddr>)>, bool), BitVMXError> {
    let guard = allow_list
        .lock()
        .map_err(|e| BitVMXError::PoisonedLockError(e.to_string()))?;
    Ok((guard.entries(), guard.is_allow_all()))
}

/// Apply `change` to the allow list and persist the result, reporting whether
/// the write succeeded.
///
/// A failed write leaves the in-memory change in place: a peer we are willing
/// to talk to should not be blocked because the disk is unavailable. The
/// caller is told so it can warn that the change will not survive a restart.
pub fn mutate<F>(
    store: &Rc<Storage>,
    allow_list: &Arc<Mutex<AllowList>>,
    change: F,
) -> Result<bool, BitVMXError>
where
    F: FnOnce(&mut AllowList),
{
    let mut guard = allow_list
        .lock()
        .map_err(|e| BitVMXError::PoisonedLockError(e.to_string()))?;
    change(&mut guard);
    match save(store, &guard) {
        Ok(()) => Ok(true),
        Err(e) => {
            warn!(
                "Comms allow list changed but could not be saved: {}. \
                 The change is in effect but will be lost on restart.",
                e
            );
            Ok(false)
        }
    }
}

/// Build the comms allow list, preferring the persisted one over `yaml_path`.
pub fn build(store: &Rc<Storage>, yaml_path: &str) -> Result<Arc<Mutex<AllowList>>, BitVMXError> {
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

    /// The first API call snapshots the whole live list, so entries that came
    /// from the YAML are carried into storage rather than lost when the YAML
    /// stops being consulted.
    #[test]
    fn the_first_mutation_absorbs_the_yaml_entries() {
        let dir = test_storage_dir();
        let store = dir.storage();
        let yaml = yaml_with(&dir, "from-yaml");

        let allow_list = build(&store, &yaml).unwrap();
        mutate(&store, &allow_list, |al| {
            al.add_entry("from-api".to_string(), None)
        })
        .unwrap();

        let mut persisted = load(&store).unwrap().unwrap().entries;
        persisted.sort();
        assert_eq!(
            persisted,
            vec![
                ("from-api".to_string(), None),
                ("from-yaml".to_string(), None)
            ],
        );
    }

    #[test]
    fn re_adding_a_hash_replaces_its_address() {
        let dir = test_storage_dir();
        let store = dir.storage();
        let allow_list = AllowList::new();

        mutate(&store, &allow_list, |al| {
            al.add_entry("peer".to_string(), Some(addr("10.0.0.1")))
        })
        .unwrap();
        mutate(&store, &allow_list, |al| {
            al.add_entry("peer".to_string(), Some(addr("10.0.0.2")))
        })
        .unwrap();

        assert_eq!(
            load(&store).unwrap().unwrap().entries,
            vec![("peer".to_string(), Some(addr("10.0.0.2")))],
            "re-adding updates the address rather than creating a second entry",
        );
        let guard = allow_list.lock().unwrap();
        assert!(!guard.is_allowed(&"peer".to_string(), addr("10.0.0.1")));
        assert!(guard.is_allowed(&"peer".to_string(), addr("10.0.0.2")));
    }

    /// Entries and the blanket flag are independent: a rule added or removed
    /// while `allow_all` is on is recorded without becoming operative, and
    /// without quietly closing or opening the door.
    #[test]
    fn adding_and_removing_leave_allow_all_alone() {
        let dir = test_storage_dir();
        let store = dir.storage();
        let allow_list = AllowList::new();

        mutate(&store, &allow_list, |al| al.set_allow_all(true)).unwrap();

        mutate(&store, &allow_list, |al| {
            al.add_entry("peer".to_string(), None)
        })
        .unwrap();
        assert!(
            load(&store).unwrap().unwrap().allow_all,
            "adding a rule must not clear allow_all",
        );

        mutate(&store, &allow_list, |al| al.remove(&"peer".to_string())).unwrap();
        assert!(
            load(&store).unwrap().unwrap().allow_all,
            "removing a rule must not clear allow_all",
        );

        // and the reverse: with the flag off, neither call turns it back on
        mutate(&store, &allow_list, |al| al.set_allow_all(false)).unwrap();
        mutate(&store, &allow_list, |al| {
            al.add_entry("peer".to_string(), None)
        })
        .unwrap();
        mutate(&store, &allow_list, |al| al.remove(&"peer".to_string())).unwrap();
        assert!(
            !load(&store).unwrap().unwrap().allow_all,
            "neither call may enable allow_all",
        );
    }

    #[test]
    fn removing_an_absent_entry_is_a_no_op() {
        let dir = test_storage_dir();
        let store = dir.storage();
        let allow_list = AllowList::new();

        mutate(&store, &allow_list, |al| {
            al.add_entry("peer".to_string(), None)
        })
        .unwrap();

        let persisted = mutate(&store, &allow_list, |al| al.remove(&"ghost".to_string())).unwrap();

        assert!(persisted, "removing an absent entry still reports success");
        assert_eq!(
            load(&store).unwrap().unwrap().entries,
            vec![("peer".to_string(), None)],
            "the existing entry must be untouched",
        );
    }

    /// Locking down to nobody is a legitimate end state, and it does not lock
    /// the operator out: the API arrives over the local broker channel, not
    /// over comms.
    #[test]
    fn an_empty_list_without_allow_all_denies_everyone() {
        let dir = test_storage_dir();
        let store = dir.storage();
        let allow_list = AllowList::new();

        mutate(&store, &allow_list, |al| {
            al.add_entry("peer".to_string(), None);
            al.set_allow_all(true);
        })
        .unwrap();

        mutate(&store, &allow_list, |al| {
            al.set_allow_all(false);
            al.remove(&"peer".to_string());
        })
        .unwrap();

        let guard = allow_list.lock().unwrap();
        assert!(!guard.is_allowed(&"peer".to_string(), addr("10.0.0.1")));
        assert!(!guard.is_allowed(&"anyone".to_string(), addr("10.0.0.1")));

        let persisted = load(&store).unwrap().unwrap();
        assert!(persisted.entries.is_empty());
        assert!(!persisted.allow_all);
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

    #[test]
    fn snapshot_reports_entries_and_the_flag() {
        let allow_list = AllowList::new();
        {
            let mut guard = allow_list.lock().unwrap();
            guard.add_entry("peer".to_string(), Some(addr("10.0.0.1")));
            guard.set_allow_all(true);
        }

        let (entries, allow_all) = snapshot(&allow_list).unwrap();
        assert_eq!(entries, vec![("peer".to_string(), Some(addr("10.0.0.1")))]);
        assert!(allow_all);
    }

    #[test]
    fn mutate_applies_the_change_and_persists_it() {
        let dir = test_storage_dir();
        let store = dir.storage();
        let allow_list = AllowList::new();

        let persisted = mutate(&store, &allow_list, |al| {
            al.add_entry("peer".to_string(), None)
        })
        .unwrap();

        assert!(persisted, "a healthy store must report a successful write");
        assert!(allow_list
            .lock()
            .unwrap()
            .is_allowed(&"peer".to_string(), addr("10.0.0.1")));
        assert_eq!(
            load(&store).unwrap().unwrap().entries,
            vec![("peer".to_string(), None)],
        );
    }

    #[test]
    fn mutate_persists_a_removal() {
        let dir = test_storage_dir();
        let store = dir.storage();
        let allow_list = AllowList::new();

        mutate(&store, &allow_list, |al| {
            al.add_entry("peer".to_string(), None)
        })
        .unwrap();
        mutate(&store, &allow_list, |al| al.remove(&"peer".to_string())).unwrap();

        assert!(
            load(&store).unwrap().unwrap().entries.is_empty(),
            "the removal must reach storage, not just memory",
        );
        assert!(!allow_list
            .lock()
            .unwrap()
            .is_allowed(&"peer".to_string(), addr("10.0.0.1")));
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

        assert!(
            !guard.is_allow_all(),
            "the YAML must not reopen blanket mode"
        );
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
