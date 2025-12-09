use bitvmx_client::message_queue::MessageQueue;
use std::fs;
use std::rc::Rc;
use storage_backend::storage::Storage;
use storage_backend::storage_config::StorageConfig;
use uuid::Uuid;

#[test]
fn test_message_queue_persistence() {
    let temp_dir = format!("tmp_test_storage_{}", Uuid::new_v4());
    let config = StorageConfig {
        path: temp_dir.clone(),
        password: None,
    };

    // Create storage and queue
    let storage = Rc::new(Storage::new(&config).unwrap());
    let queue = MessageQueue::new(storage.clone());

    // Push messages
    let msg1 = vec![1, 2, 3];
    let msg2 = vec![4, 5, 6];
    queue.push_back("id1".to_string(), msg1.clone()).unwrap();
    queue.push_back("id2".to_string(), msg2.clone()).unwrap();

    // Verify pop
    let (id, msg) = queue.pop_front().unwrap().unwrap();
    assert_eq!(id, "id1");
    assert_eq!(msg, msg1);

    // Simulate restart (reload storage)
    drop(queue);
    drop(storage);

    let storage = Rc::new(Storage::new(&config).unwrap());
    let queue = MessageQueue::new(storage.clone());

    // Verify persistence
    let (id, msg) = queue.pop_front().unwrap().unwrap();
    assert_eq!(id, "id2");
    assert_eq!(msg, msg2);

    // Verify empty
    assert!(queue.pop_front().unwrap().is_none());

    // Cleanup
    drop(queue);
    drop(storage);
    fs::remove_dir_all(temp_dir).unwrap();
}
