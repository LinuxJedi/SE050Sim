pub mod types;

use std::collections::HashMap;
use std::path::PathBuf;
use types::SecureObject;

/// Hex-encoded 4-byte object ID used as JSON key.
type ObjectIdKey = String;

/// Object store backed by an in-memory HashMap with optional JSON file persistence.
pub struct ObjectStore {
    objects: HashMap<[u8; 4], SecureObject>,
    persist_path: Option<PathBuf>,
}

impl ObjectStore {
    pub fn new() -> Self {
        Self {
            objects: HashMap::new(),
            persist_path: None,
        }
    }

    pub fn with_persistence(path: PathBuf) -> Self {
        let mut store = Self {
            objects: HashMap::new(),
            persist_path: Some(path.clone()),
        };
        store.load();
        store
    }

    pub fn insert(&mut self, id: [u8; 4], obj: SecureObject) {
        self.objects.insert(id, obj);
        self.persist();
    }

    pub fn get(&self, id: &[u8; 4]) -> Option<&SecureObject> {
        self.objects.get(id)
    }

    pub fn get_mut(&mut self, id: &[u8; 4]) -> Option<&mut SecureObject> {
        self.objects.get_mut(id)
    }

    pub fn remove(&mut self, id: &[u8; 4]) -> Option<SecureObject> {
        let result = self.objects.remove(id);
        if result.is_some() {
            self.persist();
        }
        result
    }

    pub fn exists(&self, id: &[u8; 4]) -> bool {
        self.objects.contains_key(id)
    }

    pub fn list_ids(&self) -> Vec<[u8; 4]> {
        self.objects.keys().copied().collect()
    }

    pub fn clear(&mut self) {
        self.objects.clear();
        self.persist();
    }

    pub fn count(&self) -> usize {
        self.objects.len()
    }

    fn persist(&self) {
        let Some(path) = &self.persist_path else { return };
        let serializable: HashMap<ObjectIdKey, &SecureObject> = self
            .objects
            .iter()
            .map(|(k, v)| (hex::encode(k), v))
            .collect();
        if let Ok(json) = serde_json::to_string_pretty(&serializable) {
            let _ = std::fs::write(path, json);
        }
    }

    fn load(&mut self) {
        let Some(path) = &self.persist_path else { return };
        let Ok(json) = std::fs::read_to_string(path) else { return };
        let Ok(deserialized): Result<HashMap<ObjectIdKey, SecureObject>, _> =
            serde_json::from_str(&json)
        else {
            return;
        };
        for (hex_key, obj) in deserialized {
            if let Ok(bytes) = hex::decode(&hex_key) {
                if bytes.len() == 4 {
                    let mut id = [0u8; 4];
                    id.copy_from_slice(&bytes);
                    self.objects.insert(id, obj);
                }
            }
        }
    }
}

impl Default for ObjectStore {
    fn default() -> Self {
        Self::new()
    }
}
