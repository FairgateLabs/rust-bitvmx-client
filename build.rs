fn main() {
    if std::env::var("CARGO_FEATURE_CARDINAL").is_ok() {
        let my_path = std::env::var("MY_PATH").unwrap();
        let path = std::path::Path::new(&my_path);
        if !path.is_dir() {
            panic!("MY_PATH is not a directory");
        }

        for entry in std::fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            for inner_entry in std::fs::read_dir(path.clone()).unwrap() {
                let inner_entry = inner_entry.unwrap();
                let inner_path = inner_entry.path();
                let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
                let symlink_path = match path.file_name().unwrap().to_str().unwrap() {
                    "examples" => std::path::Path::new(&manifest_dir)
                        .join("examples")
                        .join(inner_path.file_name().unwrap()),
                    "tests" => std::path::Path::new(&manifest_dir)
                        .join("tests")
                        .join(inner_path.file_name().unwrap()),
                    "src" => std::path::Path::new(&manifest_dir)
                        .join("src/program/protocols")
                        .join(inner_path.file_name().unwrap()),
                    _ => continue,
                };
                
                if !symlink_path.exists() {
                    symlink(&inner_path, &symlink_path);
                }
            }
        } 
    }
}

fn symlink(src: &std::path::Path, dst: &std::path::Path) {
    #[cfg(target_os = "windows")]
    {
        std::os::windows::fs::symlink_file(src, dst).unwrap();
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        std::os::unix::fs::symlink(src, dst).unwrap();
    }
}