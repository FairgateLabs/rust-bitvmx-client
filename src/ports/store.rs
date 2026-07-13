use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use storage_backend::{
    error::StorageError,
    storage::{KeyValueStore, Storage},
};
use uuid::Uuid;

/// Object-safe key/value storage port over `serde_json::Value`.
///
/// `storage_backend::KeyValueStore` has generic `get<T>/set<T>` methods, so it cannot be a trait
/// object. This port exposes the same surface monomorphized to `Value`; call sites keep their
/// typed `get/set` through the blanket [`KeyValueStoreExt`] sugar, so switching a field from
/// `Rc<Storage>` to `Rc<dyn KeyValueStorePort>` needs no caller churn.
///
/// Transaction ids are `Uuid`s to match `storage_backend`. `None` as transaction id means
/// "direct write, unless a global transaction is active" — same semantics as `Storage`.
pub trait KeyValueStorePort {
    fn get_value(&self, key: &str, tx: Option<Uuid>) -> Result<Option<Value>, StorageError>;
    fn set_value(&self, key: &str, value: Value, tx: Option<Uuid>) -> Result<(), StorageError>;
    fn remove(&self, key: &str, tx: Option<Uuid>) -> Result<(), StorageError>;
    fn has_key(&self, key: &str, tx: Option<Uuid>) -> Result<bool, StorageError>;
    /// Keys starting with `prefix`, in ascending key order.
    fn partial_compare_keys(
        &self,
        prefix: &str,
        tx: Option<Uuid>,
    ) -> Result<Vec<String>, StorageError>;
    /// `(key, value)` pairs for keys starting with `prefix`, in ascending key order.
    fn partial_compare(
        &self,
        prefix: &str,
        tx: Option<Uuid>,
    ) -> Result<Vec<(String, Value)>, StorageError>;
    fn begin_transaction(&self) -> Uuid;
    fn commit_transaction(&self, tx: Uuid) -> Result<(), StorageError>;
    fn rollback_transaction(&self, tx: Uuid) -> Result<(), StorageError>;
    fn begin_global_transaction(&self) -> Result<(), StorageError>;
    fn commit_global_transaction(&self) -> Result<(), StorageError>;
    fn rollback_global_transaction(&self) -> Result<(), StorageError>;
}

/// Typed sugar over the object-safe port. Signatures mirror `storage_backend::KeyValueStore`
/// so existing call sites compile unchanged against `Rc<dyn KeyValueStorePort>`.
pub trait KeyValueStoreExt: KeyValueStorePort {
    fn get<T: DeserializeOwned>(
        &self,
        key: &str,
        tx: Option<Uuid>,
    ) -> Result<Option<T>, StorageError> {
        match self.get_value(key, tx)? {
            Some(value) => Ok(Some(
                serde_json::from_value(value).map_err(|_| StorageError::ConversionError)?,
            )),
            None => Ok(None),
        }
    }

    fn set<T: Serialize>(&self, key: &str, value: T, tx: Option<Uuid>) -> Result<(), StorageError> {
        let value = serde_json::to_value(value).map_err(|_| StorageError::ConversionError)?;
        self.set_value(key, value, tx)
    }
}

impl<S: KeyValueStorePort + ?Sized> KeyValueStoreExt for S {}

/// Production adapter. Routes through `Storage`'s own generic methods with `T = Value`, so the
/// on-disk serialization format (serde_json text) is unchanged.
impl KeyValueStorePort for Storage {
    fn get_value(&self, key: &str, tx: Option<Uuid>) -> Result<Option<Value>, StorageError> {
        KeyValueStore::get::<_, Value>(self, key, tx)
    }

    fn set_value(&self, key: &str, value: Value, tx: Option<Uuid>) -> Result<(), StorageError> {
        KeyValueStore::set(self, key, value, tx)
    }

    fn remove(&self, key: &str, tx: Option<Uuid>) -> Result<(), StorageError> {
        KeyValueStore::remove(self, key, tx)
    }

    fn has_key(&self, key: &str, tx: Option<Uuid>) -> Result<bool, StorageError> {
        Storage::has_key(self, key, tx)
    }

    fn partial_compare_keys(
        &self,
        prefix: &str,
        tx: Option<Uuid>,
    ) -> Result<Vec<String>, StorageError> {
        Storage::partial_compare_keys(self, prefix, tx)
    }

    fn partial_compare(
        &self,
        prefix: &str,
        tx: Option<Uuid>,
    ) -> Result<Vec<(String, Value)>, StorageError> {
        Storage::partial_compare(self, prefix, tx)?
            .into_iter()
            .map(|(key, value)| {
                let value =
                    serde_json::from_str(&value).map_err(|_| StorageError::ConversionError)?;
                Ok((key, value))
            })
            .collect()
    }

    fn begin_transaction(&self) -> Uuid {
        Storage::begin_transaction(self)
    }

    fn commit_transaction(&self, tx: Uuid) -> Result<(), StorageError> {
        Storage::commit_transaction(self, tx)
    }

    fn rollback_transaction(&self, tx: Uuid) -> Result<(), StorageError> {
        Storage::rollback_transaction(self, tx)
    }

    fn begin_global_transaction(&self) -> Result<(), StorageError> {
        Storage::begin_global_transaction(self)
    }

    fn commit_global_transaction(&self) -> Result<(), StorageError> {
        Storage::commit_global_transaction(self)
    }

    fn rollback_global_transaction(&self) -> Result<(), StorageError> {
        Storage::rollback_global_transaction(self)
    }
}
