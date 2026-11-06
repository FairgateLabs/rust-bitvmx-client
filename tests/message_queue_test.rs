use bitvmx_broker::identification::identifier::Identifier;
use bitvmx_broker::retry::RetryPolicy;
use bitvmx_broker::rpc::config::BrokerNodeConfig;
use bitvmx_client::message_queue::{MessageQueue, QueuedMessage};
use bitvmx_client::test_utils::TestStorageDir;
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn test_queue_no_starvation() {
    let dir = TestStorageDir::new("message-queue-no-starvation");
    let storage = dir.storage();

    // Create a retry policy with a small delay and limited attempts
    let retry_policy = RetryPolicy::new(&BrokerNodeConfig {
        max_msgs_per_tick_utilization: 0.5,
        max_send_attempts: 3,
        retry_min_delay_msecs: 10,
        retry_max_delay_msecs: 50,
    })
    .unwrap();

    let queue = MessageQueue::new(storage.clone(), retry_policy.clone());

    // Create poison message and valid message
    let poison_id = Identifier::new("poison".to_string(), 0);
    let good_id = Identifier::new("good".to_string(), 0);
    let poison_msg = "poison-payload".to_string();
    let good_msg = "good-payload".to_string();
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
    // Only stops a broken queue from hanging the test. The loop normally ends when the queue
    // drains, and storage writes can be slow enough that a tight deadline makes this flaky.
    let timeout = Duration::from_secs(30);

    let mut good_seen = false;
    let mut counter = 0;
    while start.elapsed() < timeout {
        if let Some(msg) = queue.pop_front().unwrap() {
            if msg.identifier == poison_id {
                counter += 1;
                queue.push_deferred(msg).unwrap();
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
}
