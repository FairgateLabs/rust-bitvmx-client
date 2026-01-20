use bitvmx_broker::channel::retry_helper::RetryPolicy;
use bitvmx_broker::identification::identifier::Identifier;
use bitvmx_client::message_queue::{MessageQueue, QueuedMessage};
use std::rc::Rc;
use std::time::{Duration, Instant};
use std::{fs, thread};
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
    let queue = MessageQueue::new(storage.clone(), RetryPolicy::default());

    // Push messages
    let msg1 = vec![1, 2, 3];
    let msg2 = vec![4, 5, 6];
    let id1 = Identifier::new("id1".to_string(), 0);
    let id2 = Identifier::new("id2".to_string(), 0);
    queue.push_new(id1.clone(), msg1.clone()).unwrap();
    queue.push_new(id2.clone(), msg2.clone()).unwrap();

    // Verify pop
    let msg = queue.pop_front().unwrap().unwrap();
    assert_eq!(msg.identifier, id1);
    assert_eq!(msg.data, msg1);

    // Simulate restart (reload storage)
    drop(queue);
    drop(storage);

    let storage = Rc::new(Storage::new(&config).unwrap());
    let queue = MessageQueue::new(storage.clone(), RetryPolicy::default());

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
    let retry_policy = RetryPolicy::default();
    let queue = MessageQueue::new(storage.clone(), retry_policy.clone());

    // Create poison message and valid message
    let poison_id = Identifier::new("poison".to_string(), 0);
    let good_id = Identifier::new("good".to_string(), 0);
    let poison_msg = vec![0xde, 0xad, 0xbe, 0xef];
    let good_msg = vec![1, 2, 3, 4];
    let poison = QueuedMessage::new(poison_id.clone(), poison_msg.clone()).unwrap();
    let good = QueuedMessage::new(good_id.clone(), good_msg.clone()).unwrap();
    // Push poison first, then valid message
    queue
        .push_new(poison.identifier.clone(), poison.data.clone())
        .unwrap();
    queue
        .push_new(good.identifier.clone(), good.data.clone())
        .unwrap();

    // Simulate repeated processing failures → requeue
    let start = Instant::now();
    let timeout =
        Duration::from_millis(retry_policy.max_delay_ms * retry_policy.max_attempts as u64);

    let mut good_seen = false;
    let mut counter = 0;
    while start.elapsed() < timeout {
        if let Some(msg) = queue.pop_front().unwrap() {
            if msg.identifier == poison_id {
                counter += 1;
                queue.push_back(msg).unwrap();
            } else if msg.identifier == good_id {
                assert_eq!(msg.data, good_msg);
                assert!(!good_seen, "Good message seen multiple times");
                good_seen = true;
            }
        }
        if queue.is_empty().unwrap() {
            break; // Poison message exhausted retries and dropped
        }
        thread::sleep(Duration::from_millis(10));
    }

    assert!(
        queue.pop_front().unwrap().is_none(),
        "Queue not empty after poison retries exhausted"
    );
    assert!(good_seen, "Good message was never processed");
    assert_eq!(
        counter, retry_policy.max_attempts as usize,
        "Poison message was not retried the expected number of times"
    );

    // Cleanup
    drop(queue);
    drop(storage);
    fs::remove_dir_all(temp_dir).unwrap();
}
