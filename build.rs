use std::process::Command;

fn main() {
    // Run git to get the current commit hash
    let output = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .expect("Failed to execute git");

    let git_hash = String::from_utf8(output.stdout).unwrap();
    // Export it as an environment variable for your code
    println!("cargo:rustc-env=GIT_HASH={}", git_hash.trim());
}
