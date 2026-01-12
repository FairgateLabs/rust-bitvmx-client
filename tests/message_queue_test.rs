use bitvmx_broker::identification::identifier::Identifier;
use bitvmx_client::message_queue::{MessageQueue, QueuedMessage, MAX_MESSAGE_RETRIES};
use std::fs;
use std::rc::Rc;
use storage_backend::storage::Storage;
use storage_backend::storage_config::StorageConfig;
use uuid::Uuid;

#[test]
fn test_message_queue_persistence() {
    let temp_dir = format!("/tmp/test_storage__{}", Uuid::new_v4());
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
    let id1 = Identifier::new("id1".to_string(), 0);
    let id2 = Identifier::new("id2".to_string(), 0);
    let queued_message1 = QueuedMessage::new(id1.clone(), msg1.clone());
    let queued_message2 = QueuedMessage::new(id2.clone(), msg2.clone());
    queue.push_back(queued_message1).unwrap();
    queue.push_back(queued_message2).unwrap();

    // Verify pop
    let msg = queue.pop_front().unwrap().unwrap();
    assert_eq!(msg.identifier, id1);
    assert_eq!(msg.data, msg1);

    // Simulate restart (reload storage)
    drop(queue);
    drop(storage);

    let storage = Rc::new(Storage::new(&config).unwrap());
    let queue = MessageQueue::new(storage.clone());

    // Verify persistence
    let msg = queue.pop_front().unwrap().unwrap();
    assert_eq!(msg.identifier, id2);
    assert_eq!(msg.data, msg2);

    // Verify empty
    assert!(queue.pop_front().unwrap().is_none());

    // Cleanup
    drop(queue);
    drop(storage);
    fs::remove_dir_all(temp_dir).unwrap();
}

#[test]
fn test_queue_no_starvation() {
    let temp_dir = format!("/tmp/test_storage_{}", Uuid::new_v4());
    let config = StorageConfig {
        path: temp_dir.clone(),
        password: None,
    };

    // Create storage and queue
    let storage = Rc::new(Storage::new(&config).unwrap());
    let queue = MessageQueue::new(storage.clone());

    // Create poison message and valid message
    let poison_id = Identifier::new("poison".to_string(), 0);
    let good_id = Identifier::new("good".to_string(), 0);
    let poison_msg = vec![0xde, 0xad, 0xbe, 0xef];
    let good_msg = vec![1, 2, 3, 4];
    let poison = QueuedMessage::new(poison_id.clone(), poison_msg.clone());
    let good = QueuedMessage::new(good_id.clone(), good_msg.clone());

    // Push poison first, then valid message
    queue
        .push_new(poison.identifier.clone(), poison.data.clone())
        .unwrap();
    queue
        .push_new(good.identifier.clone(), good.data.clone())
        .unwrap();

    // Simulate repeated processing failures → requeue
    for attempt in 0..=MAX_MESSAGE_RETRIES {
        // Process poison (should fail and be requeued)
        let msg = queue.pop_front().unwrap().unwrap();
        println!("Processing msg attempt {}: {:?}", attempt, msg);
        assert_eq!(msg.identifier, poison_id);
        assert_eq!(msg.retries, attempt);
        queue.push_back(msg).unwrap();

        // Process good (shlould fail until last attempt)
        if attempt < MAX_MESSAGE_RETRIES {
            let msg = queue.pop_front().unwrap().unwrap();
            println!("Processing msg attempt {}: {:?}", attempt, msg);
            assert_eq!(msg.identifier, good_id);
            assert_eq!(msg.data, good_msg);
            assert_eq!(msg.retries, attempt);
            queue.push_back(msg).unwrap();
        }
    }

    //Trying good message last attempt, should succeed
    let msg = queue.pop_front().unwrap().unwrap();
    assert_eq!(msg.identifier, good_id);
    assert_eq!(msg.data, good_msg);
    assert_eq!(msg.retries, MAX_MESSAGE_RETRIES);

    // Queue should now be empty, poison message dropped
    assert!(queue.pop_front().unwrap().is_none());

    // Persistence check
    drop(queue);
    drop(storage);
    let storage = Rc::new(Storage::new(&config).unwrap());
    let queue = MessageQueue::new(storage.clone());
    assert!(queue.pop_front().unwrap().is_none());

    // Cleanup
    drop(queue);
    drop(storage);
    fs::remove_dir_all(temp_dir).unwrap();
}
