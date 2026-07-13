use crate::ports::store::KeyValueStorePort;
use serde_json::Value;
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
};
use storage_backend::error::StorageError;
use uuid::Uuid;

const GLOBAL_TRANSACTION_ID: Uuid = Uuid::nil();

/// In-memory `KeyValueStorePort` with the same transaction semantics as `Storage`:
/// staged writes are visible to reads inside the same transaction (and, for the global
/// transaction, to reads with `tx = None`), applied on commit, discarded on rollback.
#[derive(Default)]
pub struct InMemoryStore {
    data: RefCell<BTreeMap<String, Value>>,
    // Per-transaction staged operations in write order; None value = staged delete.
    transactions: RefCell<HashMap<Uuid, Vec<(String, Option<Value>)>>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn global_transaction_is_active(&self) -> bool {
        self.transactions
            .borrow()
            .contains_key(&GLOBAL_TRANSACTION_ID)
    }

    /// Resolve the effective transaction for a `None` id, mirroring `Storage`.
    fn effective_tx(&self, tx: Option<Uuid>) -> Option<Uuid> {
        tx.or_else(|| {
            if self.global_transaction_is_active() {
                Some(GLOBAL_TRANSACTION_ID)
            } else {
                None
            }
        })
    }

    /// Last staged operation for `key` in `tx`, if any.
    fn staged(&self, tx: Uuid, key: &str) -> Result<Option<Option<Value>>, StorageError> {
        let map = self.transactions.borrow();
        let stage = map
            .get(&tx)
            .ok_or(StorageError::NotFound("Transaction".to_string()))?;
        Ok(stage
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone()))
    }

    fn stage(&self, tx: Uuid, key: &str, value: Option<Value>) -> Result<(), StorageError> {
        let mut map = self.transactions.borrow_mut();
        let stage = map
            .get_mut(&tx)
            .ok_or(StorageError::NotFound("Transaction".to_string()))?;
        stage.push((key.to_string(), value));
        Ok(())
    }
}

impl KeyValueStorePort for InMemoryStore {
    fn get_value(&self, key: &str, tx: Option<Uuid>) -> Result<Option<Value>, StorageError> {
        if let Some(tx) = self.effective_tx(tx) {
            if let Some(staged) = self.staged(tx, key)? {
                return Ok(staged);
            }
        }
        Ok(self.data.borrow().get(key).cloned())
    }

    fn set_value(&self, key: &str, value: Value, tx: Option<Uuid>) -> Result<(), StorageError> {
        match self.effective_tx(tx) {
            Some(tx) => self.stage(tx, key, Some(value)),
            None => {
                self.data.borrow_mut().insert(key.to_string(), value);
                Ok(())
            }
        }
    }

    fn remove(&self, key: &str, tx: Option<Uuid>) -> Result<(), StorageError> {
        match self.effective_tx(tx) {
            Some(tx) => self.stage(tx, key, None),
            None => {
                self.data.borrow_mut().remove(key);
                Ok(())
            }
        }
    }

    fn has_key(&self, key: &str, tx: Option<Uuid>) -> Result<bool, StorageError> {
        Ok(self.get_value(key, tx)?.is_some())
    }

    fn partial_compare_keys(
        &self,
        prefix: &str,
        tx: Option<Uuid>,
    ) -> Result<Vec<String>, StorageError> {
        Ok(self
            .partial_compare(prefix, tx)?
            .into_iter()
            .map(|(key, _)| key)
            .collect())
    }

    fn partial_compare(
        &self,
        prefix: &str,
        tx: Option<Uuid>,
    ) -> Result<Vec<(String, Value)>, StorageError> {
        // Merge committed data with the staged view of the effective transaction.
        let mut merged: BTreeMap<String, Option<Value>> = self
            .data
            .borrow()
            .range(prefix.to_string()..)
            .take_while(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.clone(), Some(value.clone())))
            .collect();
        if let Some(tx) = self.effective_tx(tx) {
            let map = self.transactions.borrow();
            let stage = map
                .get(&tx)
                .ok_or(StorageError::NotFound("Transaction".to_string()))?;
            for (key, value) in stage {
                if key.starts_with(prefix) {
                    merged.insert(key.clone(), value.clone());
                }
            }
        }
        Ok(merged
            .into_iter()
            .filter_map(|(key, value)| value.map(|value| (key, value)))
            .collect())
    }

    fn begin_transaction(&self) -> Uuid {
        let id = Uuid::new_v4();
        self.transactions.borrow_mut().insert(id, Vec::new());
        id
    }

    fn commit_transaction(&self, tx: Uuid) -> Result<(), StorageError> {
        let stage = self
            .transactions
            .borrow_mut()
            .remove(&tx)
            .ok_or(StorageError::NotFound("Transaction".to_string()))?;
        let mut data = self.data.borrow_mut();
        for (key, value) in stage {
            match value {
                Some(value) => {
                    data.insert(key, value);
                }
                None => {
                    data.remove(&key);
                }
            }
        }
        Ok(())
    }

    fn rollback_transaction(&self, tx: Uuid) -> Result<(), StorageError> {
        self.transactions
            .borrow_mut()
            .remove(&tx)
            .ok_or(StorageError::NotFound("Transaction".to_string()))?;
        Ok(())
    }

    fn begin_global_transaction(&self) -> Result<(), StorageError> {
        if self.global_transaction_is_active() {
            return Err(StorageError::GlobalTransactionAlreadyActiveError);
        }
        self.transactions
            .borrow_mut()
            .insert(GLOBAL_TRANSACTION_ID, Vec::new());
        Ok(())
    }

    fn commit_global_transaction(&self) -> Result<(), StorageError> {
        self.commit_transaction(GLOBAL_TRANSACTION_ID)
    }

    fn rollback_global_transaction(&self) -> Result<(), StorageError> {
        self.rollback_transaction(GLOBAL_TRANSACTION_ID)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::store::KeyValueStoreExt;
    use serde_json::json;

    #[test]
    fn set_get_remove_round_trip() {
        let store = InMemoryStore::new();
        store.set("a", 42u32, None).unwrap();
        assert_eq!(store.get::<u32>("a", None).unwrap(), Some(42));
        assert!(store.has_key("a", None).unwrap());
        store.remove("a", None).unwrap();
        assert_eq!(store.get::<u32>("a", None).unwrap(), None);
        assert!(!store.has_key("a", None).unwrap());
    }

    #[test]
    fn transaction_commit_applies_writes_in_order() {
        let store = InMemoryStore::new();
        let tx = store.begin_transaction();
        store.set("k", 1u32, Some(tx)).unwrap();
        store.set("k", 2u32, Some(tx)).unwrap();
        // Staged writes visible inside the transaction, not outside.
        assert_eq!(store.get::<u32>("k", Some(tx)).unwrap(), Some(2));
        assert_eq!(store.get::<u32>("k", None).unwrap(), None);
        store.commit_transaction(tx).unwrap();
        assert_eq!(store.get::<u32>("k", None).unwrap(), Some(2));
    }

    #[test]
    fn transaction_rollback_discards_writes() {
        let store = InMemoryStore::new();
        store.set("k", 1u32, None).unwrap();
        let tx = store.begin_transaction();
        store.remove("k", Some(tx)).unwrap();
        assert_eq!(store.get::<u32>("k", Some(tx)).unwrap(), None);
        store.rollback_transaction(tx).unwrap();
        assert_eq!(store.get::<u32>("k", None).unwrap(), Some(1));
    }

    #[test]
    fn global_transaction_routes_none_ids() {
        let store = InMemoryStore::new();
        store.begin_global_transaction().unwrap();
        assert!(store.begin_global_transaction().is_err());
        store.set("k", "v", None).unwrap();
        // Visible through None reads while the global transaction is active.
        assert_eq!(store.get::<String>("k", None).unwrap(), Some("v".into()));
        store.rollback_global_transaction().unwrap();
        assert_eq!(store.get::<String>("k", None).unwrap(), None);

        store.begin_global_transaction().unwrap();
        store.set("k", "v", None).unwrap();
        store.commit_global_transaction().unwrap();
        assert_eq!(store.get::<String>("k", None).unwrap(), Some("v".into()));
    }

    #[test]
    fn partial_compare_is_prefix_scoped_and_ordered() {
        let store = InMemoryStore::new();
        store.set_value("test2", json!("b"), None).unwrap();
        store.set_value("test1", json!("a"), None).unwrap();
        store.set_value("other", json!("x"), None).unwrap();
        assert_eq!(
            store.partial_compare("test", None).unwrap(),
            vec![
                ("test1".to_string(), json!("a")),
                ("test2".to_string(), json!("b")),
            ]
        );
        assert_eq!(
            store.partial_compare_keys("test", None).unwrap(),
            vec!["test1".to_string(), "test2".to_string()]
        );
    }

    #[test]
    fn unknown_transaction_errors() {
        let store = InMemoryStore::new();
        assert!(store.commit_transaction(Uuid::new_v4()).is_err());
        assert!(store.rollback_transaction(Uuid::new_v4()).is_err());
        assert!(store.commit_global_transaction().is_err());
        assert!(store
            .set_value("k", json!(1), Some(Uuid::new_v4()))
            .is_err());
    }
}
