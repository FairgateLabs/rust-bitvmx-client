pub enum Event {
    PegInAccepted {
        txid: String,
        amount: u64,
        address: String,
    },
}
