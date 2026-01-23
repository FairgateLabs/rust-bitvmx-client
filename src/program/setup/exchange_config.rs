/// Configuration for how data is exchanged in a step
#[derive(Debug, Clone)]
pub struct ExchangeConfig {
    /// Verify RSA signatures of messages (default: true)
    pub verify_signatures: bool,

    /// Timeout in milliseconds to wait for responses (None = no timeout)
    pub timeout_ms: Option<u64>,

    /// Number of retries if sending fails
    pub max_retries: u32,
}

impl Default for ExchangeConfig {
    fn default() -> Self {
        Self {
            verify_signatures: true,
            timeout_ms: None,
            max_retries: 3,
        }
    }
}
