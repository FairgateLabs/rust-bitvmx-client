use bitvmx_broker::identification::identifier::Identifier;
use bitvmx_broker::retry::RetryPolicy;
use bitvmx_broker::rpc::config::BrokerNodeConfig;
use bitvmx_client::message_queue::MessageQueue;
use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};
use std::fs;
use std::rc::Rc;
use storage_backend::storage::Storage;
use storage_backend::storage_config::StorageConfig;
use uuid::Uuid;

//const QUEUE_SIZES: &[usize] = &[1, 10, 100, 1_000];
//const MESSAGE_SIZES: &[usize] = &[64, 1_024, 16 * 1024, 256 * 1024, 1024 * 1024];

const QUEUE_SIZES: &[usize] = &[10, 100];
const MESSAGE_SIZES: &[usize] = &[1_024, 1024 * 1024, 8 * 1024 * 1024];

struct QueueFixture {
    queue: MessageQueue,
    _storage: Rc<Storage>,
    temp_dir: String,
}

impl QueueFixture {
    fn new() -> Self {
        let temp_dir = format!("/tmp/bitvmx_message_queue_bench_{}", Uuid::new_v4());
        let config = StorageConfig {
            path: temp_dir.clone(),
            password: None,
        };
        let storage = Rc::new(Storage::new(&config).unwrap());
        let retry_policy = RetryPolicy::new(&BrokerNodeConfig::default()).unwrap();
        let queue = MessageQueue::new(storage.clone(), retry_policy);

        Self {
            queue,
            _storage: storage,
            temp_dir,
        }
    }

    fn prefill(&self, queue_size: usize, message_size: usize) {
        for i in 0..queue_size {
            self.queue
                .push_new(identifier(i), message_payload(message_size))
                .unwrap();
        }
    }
}

impl Drop for QueueFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.temp_dir);
    }
}

fn identifier(i: usize) -> Identifier {
    Identifier::new(format!("bench-{i}"), 0)
}

fn message_payload(size: usize) -> Vec<u8> {
    // Deterministic, non-zero data so serialization/storage handles the requested payload size.
    (0..size).map(|i| (i % 251) as u8).collect()
}

fn bench_push_new(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_queue/push_new_existing_queue");
    group.sample_size(10);

    for &queue_size in QUEUE_SIZES {
        for &message_size in MESSAGE_SIZES {
            group.throughput(Throughput::Bytes(message_size as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("queue_len={queue_size}"), message_size),
                &(queue_size, message_size),
                |b, &(queue_size, message_size)| {
                    b.iter_batched(
                        || {
                            let fixture = QueueFixture::new();
                            fixture.prefill(queue_size, 64);
                            let msg = message_payload(message_size);
                            (fixture, msg)
                        },
                        |(fixture, msg)| {
                            fixture
                                .queue
                                .push_new(identifier(usize::MAX), black_box(msg))
                                .unwrap();
                        },
                        BatchSize::SmallInput,
                    );
                },
            );
        }
    }

    group.finish();
}

fn bench_pop_front(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_queue/pop_front_existing_queue");
    group.sample_size(10);

    for &queue_size in QUEUE_SIZES {
        for &message_size in MESSAGE_SIZES {
            group.throughput(Throughput::Bytes(message_size as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("queue_len={queue_size}"), message_size),
                &(queue_size, message_size),
                |b, &(queue_size, message_size)| {
                    b.iter_batched(
                        || {
                            let fixture = QueueFixture::new();
                            fixture.prefill(queue_size, message_size);
                            fixture
                        },
                        |fixture| {
                            let msg = fixture.queue.pop_front().unwrap().unwrap();
                            black_box(msg);
                        },
                        BatchSize::SmallInput,
                    );
                },
            );
        }
    }

    group.finish();
}

fn bench_drain_queue(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_queue/drain_full_queue");
    group.sample_size(10);

    for &queue_size in QUEUE_SIZES {
        for &message_size in &[1_024, 16 * 1024, 256 * 1024] {
            group.throughput(Throughput::Elements(queue_size as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("queue_len={queue_size}"), message_size),
                &(queue_size, message_size),
                |b, &(queue_size, message_size)| {
                    b.iter_batched(
                        || {
                            let fixture = QueueFixture::new();
                            fixture.prefill(queue_size, message_size);
                            fixture
                        },
                        |fixture| {
                            let mut popped = 0;
                            while fixture.queue.pop_front().unwrap().is_some() {
                                popped += 1;
                            }
                            black_box(popped);
                        },
                        BatchSize::SmallInput,
                    );
                },
            );
        }
    }

    group.finish();
}

criterion_group!(benches, bench_push_new, bench_pop_front, bench_drain_queue);
criterion_main!(benches);
