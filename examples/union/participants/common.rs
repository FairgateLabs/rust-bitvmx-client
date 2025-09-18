pub fn prefixed_name(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        return name.to_string();
    }
    format!("{}_{}", prefix, name)
}
