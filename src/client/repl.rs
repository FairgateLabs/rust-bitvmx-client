use anyhow::{Ok, Result};
use bitcoin::{OutPoint, PublicKey, XOnlyPublicKey};
use clap::{command, Parser, Subcommand, ValueEnum};
use comfy_table::Table;
use key_manager::winternitz::WinternitzPublicKey;
use p2p_handler::PeerId;
use std::fmt::Display;
use std::str::FromStr;
use uuid::Uuid;

use crate::bitvmx::BitVMX;
use crate::config::Config;
use crate::program::participant::{P2PAddress, ParticipantRole};

use super::input::InputLoop;

#[derive(Parser)]
#[command(about = "BitVMX CLI", long_about = None)]
#[command(arg_required_else_help = true)]
pub struct Menu {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    AddFunds,
    NewProgram {
        #[arg(value_name = "id", short = 'i', value_parser=clap::value_parser!(Uuid), long = "id")]
        id: Uuid,

        #[arg(value_name = "role", short = 'r', value_parser=clap::value_parser!(Role), long = "role")]
        role: Role,

        #[arg(value_name = "funding", short = 'f', long = "funding")]
        funding_tx: String,

        #[arg(value_name = "prekickoff", short = 'k', long = "prekickoff")]
        pre_kickoff: String,

        #[arg(value_name = "peer_address", short = 'a', long = "peer_address")]
        peer_address: String,

        #[arg(value_name = "peer_id", short = 'p', long = "peer_id")]
        peer_id: String,
    },

    Deploy {
        #[arg(value_name = "program_id", short = 'i')]
        program_id: String,
    },

    Program {
        #[arg(value_name = "program_id", short = 'i')]
        program_id: String,
    },

    PeerId,

    Exit,
}

#[derive(ValueEnum, Clone)]
enum Role {
    Prover,
    Verifier,
}

impl Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::Prover => write!(f, "Prover"),
            Role::Verifier => write!(f, "Verifier"),
        }
    }
}

impl From<Role> for ParticipantRole {
    fn from(role: Role) -> Self {
        match role {
            Role::Prover => ParticipantRole::Prover,
            Role::Verifier => ParticipantRole::Verifier,
        }
    }
}
pub struct Repl {
    bitvmx: BitVMX,
    input: InputLoop,
}

impl Repl {
    pub fn new() -> Result<Self> {
        let config = Config::new(None)?;
        let bitvmx = BitVMX::new(config)?;
        let input = InputLoop::new(
            "bitvmx ".to_string(),
            vec![
                "add-funds".to_string(),
                "new-program".to_string(),
                "deploy".to_string(),
                "program".to_string(),
                "peer-id".to_string(),
                "exit".to_string(),
            ],
            100,
        );

        Ok(Self { bitvmx, input })
    }

    pub fn run(&mut self) -> Result<()> {
        self.input.run();

        loop {
            let quit = self.process_input();
            if quit {
                break;
            }

            let quit = self.process_p2p_messages();
            if quit {
                break;
            }

            let quit = self.process_bitcoin_updates();
            if quit {
                break;
            }

            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        Ok(())
    }

    fn process_input(&mut self) -> bool {
        if let Some(args) = self.input.read() {
            match self.execute(args) {
                Result::Ok(quit) => return quit,
                Err(err) => {
                    self.input.write(&format!("Error with command: {:?}", err));
                }
            }
        }

        false
    }

    fn process_p2p_messages(&mut self) -> bool {
        self.bitvmx.process_p2p_messages()
    }

    fn process_bitcoin_updates(&mut self) -> bool {
        // TODO: handle error?
        self.bitvmx.process_bitcoin_updates().unwrap()
    }

    fn execute(&mut self, args: Vec<String>) -> Result<bool> {
        let menu = Menu::try_parse_from(args);
        match menu {
            Result::Ok(menu) => match &menu.command {
                Commands::AddFunds => {
                    self.add_funds()?;
                }
                Commands::NewProgram {
                    id,
                    role,
                    funding_tx,
                    pre_kickoff,
                    peer_address,
                    peer_id,
                } => {
                    self.setup_program(id, role, funding_tx, pre_kickoff, peer_address, peer_id)?;
                }
                Commands::Deploy { program_id } => {
                    let program_id = Uuid::parse_str(program_id)?;
                    self.deploy_program(&program_id)?;
                }
                Commands::Program { program_id } => {
                    let program_id = Uuid::parse_str(program_id)?;
                    self.program_details(&program_id)?;
                }
                Commands::PeerId => {
                    self.input
                        .write(&format!("My peer id is: {}", self.bitvmx.peer_id()));
                }
                Commands::Exit => {
                    return Ok(true);
                }
            },
            Err(e) => {
                let usage = e.render();
                self.input.write(&usage.to_string());
            }
        }

        Ok(false)
    }

    fn add_funds(&mut self) -> Result<()> {
        let (txid, vout, pk) = self.bitvmx.add_funds()?;
        self.input.write(&format!(
            "Funds added, funding outpoint is: {}:{} with pk: {}",
            txid, vout, pk
        ));
        Ok(())
    }

    fn setup_program(
        &mut self,
        id: &Uuid,
        role: &Role,
        funding: &str,
        pre_kickoff: &str,
        peer_address: &str,
        peer_id: &str,
    ) -> Result<()> {
        let peer_address = P2PAddress::new(peer_address, PeerId::from_str(peer_id)?);

        self.bitvmx.setup_program(
            id,
            role.clone().into(),
            OutPoint::from_str(funding)?,
            &PublicKey::from_str(pre_kickoff)?,
            &peer_address,
        )?;

        // self.program_details(&program_id.to_string())?;
        self.input.write(&format!("Setup program with id: {}", id)); //TODO: this is necessary to flush terminal

        Ok(())
    }

    fn deploy_program(&mut self, program_id: &Uuid) -> Result<()> {
        self.bitvmx.deploy_program(program_id)?;

        self.program_details(program_id)?;
        Ok(())
    }

    fn program_details(&self, program_id: &Uuid) -> Result<()> {
        let program = self.bitvmx.load_program(program_id)?;
        let prover = program.prover();
        let verifier = program.verifier();

        let (prover_drp_size, prover_drp_type) =
            fmt_option_winternitz_pks(prover.keys().as_ref().map(|k| k.dispute_resolution_keys()));
        let (verifier_drp_size, verifier_drp_type) = fmt_option_winternitz_pks(
            verifier
                .keys()
                .as_ref()
                .map(|k| k.dispute_resolution_keys()),
        );

        let mut table = Table::new();
        table
            .add_row(vec![
                format!("Program ({})\n{}", program.state(), program.id()).as_str(),
                format!(
                    "Funding tx\n{}:{}",
                    program.funding_txid(),
                    program.funding_vout()
                )
                .as_str(),
            ])
            .add_row(vec![
                "Amounts",
                format!(
                    "Funding {}\nProtocol {}\nTimelock {}\nSpeedup {}",
                    program.funding_amount(),
                    program.protocol_amount(),
                    program.timelock_amount(),
                    program.speedup_amount(),
                )
                .as_str(),
            ])
            .add_row(vec![
                "Prover p2p information",
                format!(
                    "Address {}\nPeer Id {}",
                    prover.address().address(),
                    prover.address().peer_id_bs58(),
                )
                .as_str(),
            ])
            .add_row(vec![
                "Verifier p2p information",
                format!(
                    "Address {}\nPeer Id {}",
                    verifier.address().address(),
                    verifier.address().peer_id_bs58(),
                )
                .as_str(),
            ])
            .add_row(vec![
                "Common ECDSA keys",
                format!(
                    "Internal (Taproot)\n{}\n\nProtocol\n{}",
                    fmt_option_xonly_pk(prover.keys().as_ref().map(|k| k.internal_key())),
                    fmt_option_pk(prover.keys().as_ref().map(|k| k.protocol_key())),
                )
                .as_str(),
            ])
            .add_row(vec![
                "Prover ECDSA keys",
                format!(
                    "Pre-kickoff\n{}\n\nTimelock\n{}\n\nSpeedup\n{}",
                    fmt_option_pk(prover.keys().as_ref().map(|k| k.prekickoff_key())),
                    fmt_option_pk(prover.keys().as_ref().map(|k| k.timelock_key())),
                    fmt_option_pk(prover.keys().as_ref().map(|k| k.speedup_key())),
                )
                .as_str(),
            ])
            .add_row(vec![
                "Prover dispute resolution keys",
                format!("Count {}\nType {}", prover_drp_size, prover_drp_type,).as_str(),
            ])
            .add_row(vec![
                "Verifier ECDSA keys",
                format!(
                    "Timelock\n{}\n\nSpeedup\n{}",
                    fmt_option_pk(verifier.keys().as_ref().map(|k| k.timelock_key())),
                    fmt_option_pk(verifier.keys().as_ref().map(|k| k.speedup_key())),
                )
                .as_str(),
            ])
            .add_row(vec![
                "Verifier dispute resolution keys",
                format!("Count {}\nType {}", verifier_drp_size, verifier_drp_type,).as_str(),
            ]);

        self.input.write(&format!("{table}"));
        Ok(())
    }
}

fn fmt_option_pk(key: Option<&PublicKey>) -> String {
    match key {
        Some(key) => key.to_string(),
        None => "None".to_string(),
    }
}

fn fmt_option_xonly_pk(key: Option<&XOnlyPublicKey>) -> String {
    match key {
        Some(key) => key.to_string(),
        None => "None".to_string(),
    }
}

fn fmt_option_winternitz_pks(keys: Option<&Vec<WinternitzPublicKey>>) -> (usize, String) {
    match keys {
        Some(keys) => {
            if keys.is_empty() {
                return (0, "None".to_string());
            }

            (keys.len(), keys[0].key_type().to_string())
        }
        None => (0, "None".to_string()),
    }
}
