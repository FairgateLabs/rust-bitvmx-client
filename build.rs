#[cfg(target_family = "unix")]
use std::path::Path;
#[cfg(target_family = "unix")]
use std::process::Command;

fn main() {
    #[cfg(target_family = "unix")]
    {
        println!("cargo:rustc-link-lib=dylib=stdc++");

        // --- Tell Cargo when to rerun (important!) ---
        // Re-run if the branch HEAD moves.
        println!("cargo:rerun-if-changed=.git/HEAD");
        // Re-run if the HEAD points to a branch ref and that ref moves.
        if let Some(head_ref) = read_cmd(&["symbolic-ref", "-q", "HEAD"]) {
            // e.g., "refs/heads/main"
            let ref_path = format!(".git/{}", head_ref.trim());
            println!("cargo:rerun-if-changed={}", ref_path);
        }
        // Also handle packed refs (some repos store refs here)
        if Path::new(".git/packed-refs").exists() {
            println!("cargo:rerun-if-changed=.git/packed-refs");
        }
        // If you want rebuilds when tags change (for GIT_TAG), watch tag storage too:
        // lightweight/annotated tags may live in packed-refs as well
        println!("cargo:rerun-if-changed=.git/refs/tags");

        // Optional: allow turning this off in CI
        println!("cargo:rerun-if-env-changed=GIT_INFO_DISABLE");
        if std::env::var_os("GIT_INFO_DISABLE").is_some() {
            return;
        }

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
}

#[cfg(target_family = "unix")]
fn read_cmd(args: &[&str]) -> Option<String> {
    run_git(args)
}

#[cfg(target_family = "unix")]
fn run_git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
