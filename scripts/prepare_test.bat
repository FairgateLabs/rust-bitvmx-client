rmdir /q /s \tmp\
..\rust-bitvmx-wallet\target\release\bitvmx-wallet.exe -c ..\rust-bitvmx-wallet\config\testnet.yaml import-key wallet 7092b98be432df384ce0e92a063a7fd1b2f4038d74c302c0efa5888f2a40f33c
..\rust-bitvmx-wallet\target\release\bitvmx-wallet.exe -c ..\rust-bitvmx-wallet\config\testnet.yaml add-funding wallet fund_1 7d65dd4928df55a4a1d92e3fe34f4b16215b588e7c9209569a5ba45ad03cd52f:1 535747
python scripts\testnet.py
cargo test --release -- --ignored test_independent_testnet