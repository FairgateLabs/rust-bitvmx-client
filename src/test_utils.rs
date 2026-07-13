use std::rc::Rc;
use std::{env, fs};

use storage_backend::storage::Storage;
use storage_backend::storage_config::StorageConfig;
use uuid::Uuid;

/// Temporary storage directory for unit tests. Creates a unique path under the
/// system temp dir and removes it on drop.
pub struct TestStorageDir {
    path: String,
}

impl TestStorageDir {
    pub fn new(prefix: &str) -> Self {
        Self {
            path: env::temp_dir()
                .join(format!("{}-{}", prefix, Uuid::new_v4()))
                .to_string_lossy()
                .into_owned(),
        }
    }

    pub fn config(&self) -> StorageConfig {
        StorageConfig {
            path: self.path.clone(),
            password: None,
        }
    }

    pub fn storage(&self) -> Rc<Storage> {
        Rc::new(Storage::new(&self.config()).unwrap())
    }
}

impl Drop for TestStorageDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
