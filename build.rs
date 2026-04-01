use std::process::Command;

fn main() {
    {
        // check if .git is a file or a directory
        let git_path = std::path::Path::new(".git");
        if git_path.is_file() {
            // If it's a file, read the contents to find the actual git directory
            if let Ok(contents) = std::fs::read_to_string(git_path) {
                if let Some(git_dir) = contents.trim().strip_prefix("gitdir: ") {
                    println!("cargo:rerun-if-changed={}/HEAD", git_dir);
                    println!("cargo:rerun-if-changed={}/refs/tags", git_dir);
                    println!("cargo:rerun-if-changed={}/refs/heads", git_dir);
                }
            }
        } else {
            // If it's a directory, watch it directly
            println!("cargo:rerun-if-changed=.git/HEAD");
            println!("cargo:rerun-if-changed=.git/refs/tags");
            println!("cargo:rerun-if-changed=.git/refs/heads");
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

fn run_git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
