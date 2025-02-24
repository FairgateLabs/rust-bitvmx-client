# BitVMX Client
The BitVMX Client provides the core functionality for interacting with BitVMX protocol and the Bitcoin blockchain.

## Installation
Clone the repository and initialize the submodules:
```bash
$ git clone git@github.com:FairgateLabs/rust-bitvmx-client.git
```

## Build

```bash
cargo build
```


## Pre requisits

You will need to have access to a bitcoin node.

## Run a client

There are 3 configurations develoment, prover and verifier. They can be found at [config](./config/). To choose betwen them you should set the `BITVMX_ENV` env variable, default is development.

You can run it using 

```bash
cargo run --release -- --configuration config/prover.yaml
```

or 

```bash
cargo run --release -- --configuration config/verifier.yaml
```

If no bitvmx flag is added it will default to prover

### Peer id and address

After running it the first thig we will see is the id and and address (ip and port)

```
INFO Peer ID: 12D3KooWAKhpiQGyGt1YtYm948gRCU8JEE9nabLPTnvVQYKEtcwZ
bitvmx »  INFO Listening on /ip4/127.0.0.1/tcp/61180
```

Prover is currently run at 61180 while the Verifier is run at 61181
Peer ID is generated using the key on the config file

### Development

In order to run bitvmx-client in development you will need a regtest bitcoin node that accepts incomming rpc calls. You can do this by configuring the following flags in the bitcoin.conf file or add them as flags in the bitcoin-cli command line.

```conf
# Bitcoin config file example
# https://gist.github.com/huxley-sparks/943278

# server=1 tells Bitcoin to accept JSON-RPC commands.
server=1
# Network Options
regtest=1
# RPC Options
rpcuser=foo
rpcpassword=rpcpassword
regtest.rpcport=18443
# Set default fee rate https://bitcoin.stackexchange.com/questions/97174/when-using-bitcoin-cli-i-get-an-error-regarding-fallback-fees-when-trying-to-sen
fallbackfee=0.00001
```

The client will use default test_wallet, you can add it and check it's information by running

```bash
bitcoin-cli create test_wallet
bitcoin-cli loadwallet test_wallet 
bitcoin-cli listwallets
bitcoin-cli getwalletinfo
```
  
## User journey

1- [Run a prover](#run-a-client)
2- [Run a verifier](#run-a-client)
3- Use the prover client to [add funds](#add-funds)
4- Use the prover client to create a [new program](#new-program)
5- Use the prover to deploy a program
