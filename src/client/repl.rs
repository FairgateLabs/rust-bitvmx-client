use anyhow::{Ok, Result};
use bitcoin::{OutPoint, PublicKey, XOnlyPublicKey};
use comfy_table::Table;
use p2p_handler::PeerId;
use uuid::Uuid;
use std::str::FromStr;
use clap::{command, Parser, Subcommand, ValueEnum};
use key_manager::winternitz::WinternitzPublicKey;

use crate::bitvmx::BitVMX;
use crate::config::Config;
use crate::errors::ConfigError;
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
        #[arg(value_name = "role", short = 'r', value_parser=clap::value_parser!(Role), long = "role")]
        role: Role,

        #[arg(value_name = "funding", short = 'f', long = "funding")]
        funding_tx: String,

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

impl ToString for Role {
    fn to_string(&self) -> String {
        match self {
            Role::Prover => "Prover".to_string(),
            Role::Verifier => "Verifier".to_string(),
        }
    }
}

impl Into<ParticipantRole> for Role {
    fn into(self) -> ParticipantRole {
        match self {
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
    pub fn new(config: Option<String>) -> Result<Self> {
        let config = Config::new(config)?;
        let bitvmx = BitVMX::new(&config)?;
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
            100
        );

        let program_home = config.program_home();
        std::fs::create_dir_all(&program_home).map_err(
            |_| ConfigError::ProgramPathError(program_home.to_string_lossy().into_owned())
        )?;

        Ok(Self {
            bitvmx,
            input,
        })
    }

    pub fn run(&mut self) -> Result<()> {
        self.input.run();

        loop {
            let quit =  self.process_input();
            if quit { break }

            let quit = self.process_p2p_messages();
            if quit { break }

            let quit = self.process_bitcoin_updates();
            if quit { break }

            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        Ok(())
    }

    fn process_input(&mut self) -> bool {
        if let Some(args) = self.input.read() {
            match self.execute(args) {
                Result::Ok(quit) => {
                    return quit
                }
                Err(err) => {
                    self.input.write(&format!("Error with command: {:?}", err));
                }
            }
        }
            
        false
    }

    fn process_p2p_messages(&self) -> bool {
        self.bitvmx.process_p2p_messages()
    }

    fn process_bitcoin_updates(&mut self) -> bool {
        self.bitvmx.process_bitcoin_updates() 
    }

    fn execute(&mut self, args: Vec<String>) -> Result<bool> {
        let menu = Menu::try_parse_from(args);
        match menu {
            Result::Ok(menu) => {
                match &menu.command {
                    Commands::AddFunds => {
                        self.add_funds()?;
                    }
                    Commands::NewProgram { role, funding_tx, peer_address, peer_id } => {
                        self.setup_program(role, funding_tx, peer_address, peer_id)?; 
                    },
                    Commands::Deploy { program_id } => {
                        self.deploy_program(program_id)?; 
                    },
                    Commands::Program { program_id } => {
                        self.program_details(program_id)?;
                    },
                    Commands::PeerId => {
                        self.input.write(&format!("My peer id is: {}", self.bitvmx.peer_id()));
                    }
                    Commands::Exit => {
                        return Ok(true);
                    }
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
        let (txid, vout) = self.bitvmx.add_funds()?;
        self.input.write(&format!("Funds added, funding outpoint is: {}:{}", txid, vout));
        Ok(())
    }

    fn setup_program(&mut self, role: &Role, funding: &String, peer_address: &String, peer_id: &String) -> Result<()> {
        let peer_address = P2PAddress::new(peer_address, PeerId::from_str(peer_id)?);

        let program_id = self.bitvmx.setup_program(
            role.clone().into(), 
            OutPoint::from_str(funding)?, 
            &peer_address
        )?;

        // self.program_details(&program_id.to_string())?;
        Ok(())
    }

    fn deploy_program(&mut self, program_id: &str) -> Result<()> {
        let program_id = Uuid::parse_str(program_id)?;
        self.bitvmx.deploy_program(program_id)?;

        self.program_details(&program_id.to_string())?;
        Ok(())
    } 
    
    fn program_details(&self, program_id: &str) -> Result<()> {
        let program_id = Uuid::parse_str(program_id)?;
        let program = self.bitvmx.program(program_id)?;
        let prover = program.prover();
        let verifier = program.verifier();

        let (prover_drp_size, prover_drp_type) = fmt_option_winternitz_pks(prover.dispute_resolution_keys());
        let (verifier_drp_size, verifier_drp_type) = fmt_option_winternitz_pks(verifier.dispute_resolution_keys());

        let mut table = Table::new();
        table.add_row(vec![
            format!("Program ({})\n{}", program.state(), program.id()).as_str(),
            format!("Funding tx\n{}:{}", program.funding_txid(), program.funding_vout()).as_str(),
        ]).add_row(vec![
            "Amounts",
            format!(
                "Funding {}\nProtocol {}\nTimelock {}\nSpeedup {}", 
                program.funding_amount(),
                program.protocol_amount(),
                program.timelock_amount(),
                program.speedup_amount(),
            ).as_str(),
        ]).add_row(vec![
            "Prover p2p information", 
            format!(
                "Address {}\nPeer Id {}", 
                prover.address().address(),
                prover.address().peer_id_bs58(),
            ).as_str(),
        ]).add_row(vec![
            "Verifier p2p information", 
            format!(
                "Address {}\nPeer Id {}", 
                verifier.address().address(),
                verifier.address().peer_id_bs58(),
            ).as_str(),
        ]).add_row(vec![
            "Common ECDSA keys",
            format!(
                "Internal (Taproot)\n{}\n\nProtocol\n{}", 
                fmt_option_xonly_pk(prover.internal_key()),
                fmt_option_pk(prover.protocol_key()),
            ).as_str(),
        ]).add_row(vec![
            "Prover ECDSA keys",
            format!(
                "Pre-kickoff\n{}\n\nTimelock\n{}\n\nSpeedup\n{}", 
                fmt_option_pk(prover.prekickoff_key()),
                fmt_option_pk(prover.timelock_key()),
                fmt_option_pk(prover.speedup_key()),
            ).as_str(),
        ]).add_row(vec![
            "Prover dispute resolution keys",
            format!(
                "Count {}\nType {}", 
                prover_drp_size,
                prover_drp_type,
            ).as_str(),
        ]).add_row(vec![
            "Verifier ECDSA keys",
            format!(
                "Timelock\n{}\n\nSpeedup\n{}", 
                fmt_option_pk(verifier.timelock_key()),
                fmt_option_pk(verifier.speedup_key()),
            ).as_str(),
        ]).add_row(vec![
            "Verifier dispute resolution keys",
            format!(
                "Count {}\nType {}", 
                verifier_drp_size,
                verifier_drp_type,
            ).as_str(),
        ]);

        self.input.write(&format!("{table}"));
        Ok(())
    }

}

fn fmt_option_pk(key: Option<PublicKey>) -> String {
    match key {
        Some(key) => key.to_string(),
        None => "None".to_string(),
    }
}

fn fmt_option_xonly_pk(key: Option<XOnlyPublicKey>) -> String {
    match key {
        Some(key) => key.to_string(),
        None => "None".to_string(),
    }
}

fn fmt_option_winternitz_pks(keys: Option<Vec<WinternitzPublicKey>>) -> (usize, String) {
    match keys {
        Some(keys) => {
            if keys.len() == 0 {
                return (0, "None".to_string())
            }

            (keys.len(), keys[0].key_type().to_string())
        },
        None => (0, "None".to_string()),
    }
}