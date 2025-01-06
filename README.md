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
cargo run --release --bin bitvmx -- prover
```

or 

```bash
cargo run --release --bin bitvmx -- verifier
```

If no bitvmx flag is added it will default to prover

### Peer id and address

After running it the first thig we will see is the id and and address (ip and port)

```
INFO Peer ID: 12D3KooWAKhpiQGyGt1YtYm948gRCU8JEE9nabLPTnvVQYKEtcwZ
bitvmx »  INFO Listening on /ip4/127.0.0.1/tcp/61180
```

Prover is currently run at 61180 while the Verifier is run at 61181

**NOTE**
PEER ID IS GENERATED RANDOMLY, AFTER KEVING PUSH IT SHOULD TAKE THE ONE IN THE [config](./config/) .json FILE. IN THE MEANWHILE WE ARE MODIFYING THE P2P LIST AT [p2p-protocol/src/allow_list.rs](../rust-p2p-protocol/src/allow_list.rs)

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
bitcoin-cli loadwallet test_wallet 
bitcoin-cli listwallets
bitcoin-cli getwalletinfo
```


## Commands

Commands:
  add-funds    
  new-program  
  deploy       
  program      
  peer-id      
  exit         
  help 


### Add funds

Usage:  

```bash
bitvmx » add-funds 
```

Funds 1 BTC to the address obtained from `key_manager` at [config](./config/) .json using the bitcoin wallet set up in the same file.

Output is the transaction id (Transaction::compute_wtxid). For example:

```
Funds added, funding outpoint is: ea25e87f729018511538b453fe7e4aabc0f1ea8687b254d39c4196d112681c9b:0

```


### Peer Id

Usage:  

```bash
bitvmx » peer-id
```

It shows the current client peer id like

```
My peer id is: 12D3KooWAKhpiQGyGt1YtYm948gRCU8JEE9nabLPTnvVQYKEtcwZ
```

### New program

Usage:

```bash
bitvmx » new-program --role <role> --funding <funding> --peer_address <peer_address> --peer_id <peer_id>
```

Options:
  -r, --role <role>                  [possible values: prover, verifier]
  -f, --funding <funding>            txId obtained at [add-funds](#add-funds)
  -a, --peer_address <peer_address>  ip:port from the peer (not ours) obtained [at startup](#peer-id-and-address) on the peer
  -p, --peer_id <peer_id>            id from the peer (not ours), can be obtained using [peer-id](#peer-id) on the peer 
  -h, --help                         Print help

Example:

```bash
bitvmx » new-program --role prover --funding ea25e87f729018511538b453fe7e4aabc0f1ea8687b254d39c4196d112681c9b:0 --peer_address /ip4/127.0.0.1/tcp/61181 --peer_id 12D3KooWNiCPAyuQhLoqsbaSqvUCgAChN4wqNEhBfr5Nz6a77E3K
```

Output will be like

```
INFO Connected to 12D3KooWCL2CbGe2uHPo5CSPy7SuWSji9RjP18hRwVdvdMFK8uuC
INFO Peer 12D3KooWCL2CbGe2uHPo5CSPy7SuWSji9RjP18hRwVdvdMFK8uuC connected
Setup program with id: 6a3367ec-5341-447e-abd7-29e9d8dc5b67
```


### Program

Gets the details of a program. Usage: 

```bash
bitvmx » input program -i <program_id>
```

The program is obtained from the [new program output](#new-program)

Example:

```bash
bitvmx » program -i 6a3367ec-5341-447e-abd7-29e9d8dc5b67
```

  
## User journey

1- [Run a prover](#run-a-client)
2- [Run a verifier](#run-a-client)
3- Use the prover client to [add funds](#add-funds)
4- Use the prover client to create a [new program](#new-program)
5- Use the prover to deploy a program
