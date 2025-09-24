use std::process::Command;

fn main() {
    // Git tag (may be empty if no tag points at HEAD)
    let git_tag = run_git(&["tag", "--points-at", "HEAD"]).unwrap_or_else(|| "None".into());
    println!("cargo:rustc-env=GIT_TAG={}", git_tag);

    // Git hash
    let git_hash = run_git(&["rev-parse", "--short", "HEAD"]).unwrap_or_else(|| "None".into());
    println!("cargo:rustc-env=GIT_HASH={}", git_hash);

    // Git commit message
    let git_message =
        run_git(&["show", "-s", "--format=%s", "HEAD"]).unwrap_or_else(|| "None".into());
    println!("cargo:rustc-env=GIT_MESSAGE={}", git_message);

    // Git commit date
    let git_date =
        run_git(&["show", "-s", "--format=%ci", "HEAD"]).unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=GIT_DATE={}", git_date);
}

fn run_git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
