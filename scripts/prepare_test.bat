rmdir /q /s \tmp\
..\rust-bitvmx-wallet\target\release\bitvmx-wallet.exe -c ..\rust-bitvmx-wallet\config\testnet.yaml import-key wallet 7092b98be432df384ce0e92a063a7fd1b2f4038d74c302c0efa5888f2a40f33c
..\rust-bitvmx-wallet\target\release\bitvmx-wallet.exe -c ..\rust-bitvmx-wallet\config\testnet.yaml add-funding wallet fund_1 e94d295decbe9060ab16899f2f1d82e4dcbd6f8c23e83b5bdfbe91ff6cfb4b2a:1 7510345
python testnet.py
cargo test --release -- --ignored test_independent_testnet