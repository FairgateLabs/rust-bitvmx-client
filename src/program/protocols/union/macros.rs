#[macro_export]
macro_rules! send_to_l2 {
    ($self:ident, $program_context:ident, $msg_type:ty, $payload:expr) => {{
        let data = serde_json::to_string(&OutgoingBitVMXApiMessages::Variable(
            $self.ctx.id,
            <$msg_type>::name(),
            VariableTypes::String(serde_json::to_string(&$payload)?),
        ))?;

        $program_context
            .broker_channel
            .send(&$program_context.components_config.l2, data.clone())?;

        data
    }};
}
