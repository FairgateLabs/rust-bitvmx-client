#[macro_export]
macro_rules! expect_msg {
    ($self:expr, $pattern:pat => $expr:expr) => {{
        let msg = $self
            .bitvmx
            .wait_message(Some(std::time::Duration::from_secs(20)), None)?;

        if let $pattern = msg {
            Ok($expr)
        } else {
            Err(anyhow::anyhow!(
                "Expected `{}` but got `{:?}`",
                stringify!($pattern),
                msg
            ))
        }
    }};
}
