use std::process::Command;

fn main() {
    let git_hash = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output();

    match git_hash {
        Ok(output) if output.status.success() => {
            let hash = String::from_utf8_lossy(&output.stdout);
            println!("cargo:rustc-env=GIT_HASH={}", hash.trim());
        }
        _ => {
            eprintln!("cargo:warning=⚠️  git not found or failed to get commit hash");
            // Provide a fallback value so compilation still works
            println!("cargo:rustc-env=GIT_HASH=unknown");
        }
    }
}
