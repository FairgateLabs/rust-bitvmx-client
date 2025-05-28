rmdir /q /s \tmp\regtest
cargo test --release -- --ignored test_prepare_bitcoin
rem ..\rust-bitvmx-wallet\target\release\bitvmx-wallet.exe -c ..\rust-bitvmx-wallet\config\regtest.yaml create-wallet wallet
cargo test --release -- --ignored test_independent_regtest