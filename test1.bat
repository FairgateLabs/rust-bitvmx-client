REM test
call ..\stop.bat
call ..\start.bat
rmdir /s /q \tmp\verifier  
rmdir /s /q \tmp\prover  
SET RUST_BACKTRACE=1
cargo run --release --example single_run
