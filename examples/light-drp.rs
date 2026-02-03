#[path = "common/log.rs"]
mod log;
#[path = "common/macros.rs"]
mod macros;

use std::thread;
use std::time::Duration;

use anyhow::Result;
use bitcoin::PublicKey;
use bitvmx_client::types::OutgoingBitVMXApiMessages;
use bitvmx_client::{client::BitVMXClient, config::Config, program::participant::CommsAddress};
use bitvmx_operator_comms::operator_comms::AllowList;
use tracing::{info, info_span};
use uuid::Uuid;

pub fn main() -> Result<()> {
    log::configure_tracing();

    let mut operators = vec![
        Operator::new("op_1")?,
        Operator::new("op_2")?,
        Operator::new("op_3")?,
        Operator::new("op_4")?,
    ];

    info!("Getting peer info for operators...");
    all(&mut operators, |o| o.get_peer_info())?;
    info!("done");

    all(&mut operators, |o| o.say_hi())?;

    Ok(())
}

struct Operator {
    id: String,
    config: Config,
    address: Option<CommsAddress>,
    bitvmx: BitVMXClient,
    aggregated_key: Option<PublicKey>,
}

impl Operator {
    pub fn new(id: &str) -> Result<Self> {
        let config = Config::new(Some(format!("config/{}.yaml", id)))?;
        let allow_list = AllowList::from_file(&config.broker.allow_list)?;
        let bitvmx = BitVMXClient::new(
            &config.components,
            &config.broker,
            &config.testing.l2,
            allow_list,
        )?;

        Ok(Self {
            id: id.to_string(),
            config,
            address: None,
            bitvmx,
            aggregated_key: None,
        })
    }

    pub fn get_peer_info(&mut self) -> Result<CommsAddress> {
        self.bitvmx.get_comm_info(Uuid::new_v4())?;
        // thread::sleep(std::time::Duration::from_secs(5));
        let addr = wait_until_msg!(
            &self.bitvmx,
            OutgoingBitVMXApiMessages::CommInfo(_, _addr) => _addr
        );

        self.address = Some(addr.clone());
        Ok(addr)
    }

    pub fn say_hi(&self) -> Result<()> {
        info!(
            "Hello, I am {} at {}",
            self.id,
            self.address.as_ref().unwrap()
        );

        Ok(())
    }
}

fn all<F, R>(operators: &mut Vec<Operator>, f: F) -> Result<Vec<R>>
where
    F: Fn(&mut Operator) -> Result<R> + Send + Sync + Clone,
    R: Send,
{
    thread::scope(|s| {
        operators
            .iter_mut()
            .map(|o| {
                let f = f.clone();
                let span = info_span!("operator", id = %o.id);

                thread::sleep(Duration::from_millis(2000)); // Simulate some delay for each member

                s.spawn(move || span.in_scope(|| f(o)))
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect()
    })
}
