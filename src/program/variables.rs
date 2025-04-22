use std::rc::Rc;

use storage_backend::storage::{KeyValueStore, Storage};
use uuid::Uuid;

use crate::{errors::BitVMXError, types::VariableTypes};

pub struct Globals {
    storage: Rc<Storage>,
}

impl Globals {
    pub fn new(storage: Rc<Storage>) -> Self {
        Self { storage }
    }

    pub fn set_var(&self, uuid: &Uuid, key: &str, value: VariableTypes) -> Result<(), BitVMXError> {
        let key = format!("{}:{}", uuid, key);
        Ok(self.storage.set(&key, value, None)?)
    }

    pub fn get_var(&self, uuid: &Uuid, key: &str) -> Result<Option<VariableTypes>, BitVMXError> {
        let key = format!("{}:{}", uuid, key);
        let value = self.storage.get(&key)?;
        Ok(value)
    }
}
