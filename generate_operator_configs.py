#!/usr/bin/env python3
"""
Operator Configuration Generator

This script generates BitVMX operator configuration files based on the patterns
found in the existing op_1.yaml through op_4.yaml files.

Usage:
    python generate_operator_configs.py --operator 5 --generate-keys
    python generate_operator_configs.py --operator 6 --mnemonic "your twelve word mnemonic phrase here" --generate-keys
    python generate_operator_configs.py --batch-start 5 --batch-end 10 --generate-keys --output-dir config/

SSH Key Generation Command: ssh-keygen -t rsa -b 2048 -o -a 100 -f config/keys/op_n.key -N "" -m PKCS8
"""

import argparse
import yaml
import subprocess
import os
from pathlib import Path
from typing import Dict, Any, List


class OperatorConfigGenerator:
    """Generates operator configuration files with the correct patterns."""

    def __init__(self):
        """Initialize the generator with base configuration template."""
        self.base_config = {
            "bitcoin": {
                "network": "regtest",
                "url": "http://127.0.0.1:18443/",
                "username": "foo",
                "password": "rpcpassword",
                "wallet": "test_wallet"
            },
            "key_manager": {
                "network": "regtest",
                "key_derivation_path": "m/101/1/0/0/",
                "mnemonic_passphrase": ""
            },
            "broker": {
                "settings": "config/broker_settings.yaml",
                "allow_list": "config/broker_allow_list.yaml",
                "routing_table": "config/routing_table.yaml",
                "ip": "127.0.0.1",
                "priv_key": "config/keys/services.key"
            },
            "components": {
                "l2": {
                    "pubkey_hash": "7005e4a0325b644baa2b66c3fa2ed2a795cae584b6d3a57ca45ebf5d0eb0011f",
                    "id": 0
                },
                "bitvmx": {
                    "pubkey_hash": "1d10fa43ebbf6674d74caa3e9032711ade09d98ea7d20f89459f61152bebda1e",
                    "id": 0
                },
                "emulator": {
                    "pubkey_hash": "c356750c04776008418c31cb1fd3d9dad936e5487358eeb8961b68831f419125",
                    "id": 0
                },
                "prover": {
                    "pubkey_hash": "054dba5c41ee2926a7d909cc3443fa78f2f2e257cb1d008fd75e0d3534e3ba0d",
                    "id": 0
                },
                "garbler": {
                    "pubkey_hash": "cca0b69255be0d66bc92fdc219425c51fffc15d90f4cc75574e77a284646bcf2",
                    "id": 0
                }
            },
            "testing": {
                "l2": {
                    "priv_key": "config/keys/l2.key",
                    "id": 0
                },
                "emulator": {
                    "priv_key": "config/keys/emulator.key",
                    "id": 0
                },
                "prover": {
                    "priv_key": "config/keys/prover.key",
                    "id": 0
                },
                "garbler": {
                    "priv_key": "config/keys/garbler.key",
                    "id": 0
                }
            },
            "coordinator_throttle": {
                "init_interval": 10,
                "busy_interval": 50,
                "idle_interval": 200
            },
            "bitvmx_throttle": {
                "busy_interval": 20,
                "idle_interval": 200
            },
            "job_dispatcher_ping": {
                "enabled": True,
                "interval_secs": 120,
                "timeout_secs": 30,
                "services": ["Emulator", "Garbler"]
            },
            "client": {
                "retry": 1,
                "retry_delay": 1000
            },
            "wallet": {
                "start_height": 0
            }
        }

    def generate_ssh_key(self, operator_num: int, keys_dir: str = "config/keys") -> str:
        """
        Generate SSH key for the operator using ssh-keygen.

        Args:
            operator_num: Operator number
            keys_dir: Directory to store the keys

        Returns:
            Path to the generated key file
        """
        keys_path = Path(keys_dir)
        keys_path.mkdir(parents=True, exist_ok=True)

        key_file = keys_path / f"op_{operator_num}.key"

        # SSH-keygen command as specified - PKCS#8 ASN.1 format
        cmd = [
            "ssh-keygen",
            "-t", "rsa",
            "-b", "2048",
            "-o",
            "-a", "100",
            "-f", str(key_file),
            "-N", "",  # No passphrase
            "-m", "PKCS8"
        ]

        try:
            # Run ssh-keygen command
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            print(f"Generated SSH key: {key_file}")
            if result.stdout:
                print(f"SSH-keygen output: {result.stdout.strip()}")
            return str(key_file)
        except subprocess.CalledProcessError as e:
            print(f"Error generating SSH key for operator {operator_num}: {e}")
            if e.stderr:
                print(f"Error details: {e.stderr}")
            raise
        except FileNotFoundError:
            print("Error: ssh-keygen not found. Please ensure OpenSSH is installed.")
            raise

    def generate_config(self, operator_num: int, mnemonic: str = None) -> Dict[str, Any]:
        """
        Generate configuration for a specific operator.

        Args:
            operator_num: The operator number (1, 2, 3, etc.)
            mnemonic: BIP39 mnemonic phrase. If None, uses empty string.

        Returns:
            Dictionary containing the complete configuration
        """
        config = self.base_config.copy()

        # Use provided mnemonic or default to empty string
        if mnemonic is None:
            mnemonic = ""

        # Add operator-specific configurations
        config["key_manager"]["mnemonic_sentence"] = mnemonic

        # Password pattern: SeCrEt_p4ssw0rd_{operator_num + 1}!
        config["key_storage"] = {
            "password": f"SeCrEt_p4ssw0rd_{operator_num + 1}!",
            "path": f"/tmp/regtest/op_{operator_num}/keys.db"
        }

        config["storage"] = {
            "path": f"/tmp/regtest/op_{operator_num}/storage.db"
        }

        # Communication address pattern: 61180 + (operator_num - 1)
        config["comms"] = {
            "address": f"127.0.0.1:{61180 + (operator_num - 1)}",
            "priv_key": f"config/keys/op_{operator_num}.key",
            "storage_path": f"/tmp/regtest/op_{operator_num}/comms.db",
            "allow_list": "config/comms_allow_list.yaml"
        }

        # Broker port pattern - using 20000+ range to avoid macOS conflicts and stay under 65000
        # Pattern: 20222, 20333, 20444, 20555, etc.
        broker_port = 20000 + (operator_num * 111) + 111  # 20222, 20333, 20444, 20555...

        config["broker"]["port"] = broker_port
        config["broker"]["storage"] = {
            "path": f"/tmp/regtest/op_{operator_num}/broker.db"
        }

        config["wallet"]["db_path"] = f"/tmp/regtest/op_{operator_num}/wallet.db"

        return config

    def save_config(self, config: Dict[str, Any], operator_num: int, output_dir: str = "config",
                   generate_keys: bool = False) -> str:
        """
        Save configuration to YAML file and optionally generate SSH keys.

        Args:
            config: Configuration dictionary
            operator_num: Operator number for filename
            output_dir: Directory to save the file
            generate_keys: Whether to generate SSH keys

        Returns:
            Path to the saved file
        """
        output_path = Path(output_dir) / f"op_{operator_num}.yaml"
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Generate SSH keys if requested
        if generate_keys:
            try:
                keys_dir = Path(output_dir) / "keys"
                self.generate_ssh_key(operator_num, str(keys_dir))
            except Exception as e:
                print(f"Warning: Failed to generate SSH key for operator {operator_num}: {e}")

        with open(output_path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False, indent=2)

        return str(output_path)

    def generate_batch(self, start_num: int, end_num: int, output_dir: str = "config",
                      custom_mnemonics: Dict[int, str] = None, generate_keys: bool = False) -> list[str]:
        """
        Generate multiple operator configurations.

        Args:
            start_num: Starting operator number
            end_num: Ending operator number (inclusive)
            output_dir: Output directory
            custom_mnemonics: Dictionary mapping operator numbers to custom mnemonics
            generate_keys: Whether to generate SSH keys for each operator

        Returns:
            List of paths to generated files
        """
        generated_files = []
        custom_mnemonics = custom_mnemonics or {}

        for op_num in range(start_num, end_num + 1):
            mnemonic = custom_mnemonics.get(op_num)
            config = self.generate_config(op_num, mnemonic)
            file_path = self.save_config(config, op_num, output_dir, generate_keys)
            generated_files.append(file_path)
            print(f"Generated: {file_path}")

        return generated_files


def main():
    """Main CLI interface."""
    parser = argparse.ArgumentParser(
        description="Generate BitVMX operator configuration files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate single operator config
  python generate_operator_configs.py --operator 5

  # Generate with SSH keys
  python generate_operator_configs.py --operator 6 --generate-keys

  # Generate with custom mnemonic and keys
  python generate_operator_configs.py --operator 6 --mnemonic "your custom twelve word mnemonic phrase goes here" --generate-keys

  # Generate batch of operators with keys
  python generate_operator_configs.py --batch-start 5 --batch-end 10 --generate-keys

  # Generate to specific directory
  python generate_operator_configs.py --operator 7 --output-dir custom_configs/ --generate-keys
        """
    )

    # Single operator generation
    parser.add_argument("--operator", type=int, help="Generate config for specific operator number")
    parser.add_argument("--mnemonic", type=str, help="Custom BIP39 mnemonic phrase (12 words)")

    # Batch generation
    parser.add_argument("--batch-start", type=int, help="Start of operator range for batch generation")
    parser.add_argument("--batch-end", type=int, help="End of operator range for batch generation (inclusive)")

    # Output options
    parser.add_argument("--output-dir", type=str, default="config",
                       help="Output directory (default: config)")
    parser.add_argument("--generate-keys", action="store_true",
                       help="Generate SSH keys using ssh-keygen")
    parser.add_argument("--list-existing", action="store_true",
                       help="List existing operator config files")

    args = parser.parse_args()

    generator = OperatorConfigGenerator()

    if args.list_existing:
        config_dir = Path(args.output_dir)
        if config_dir.exists():
            existing = list(config_dir.glob("op_*.yaml"))
            if existing:
                print("Existing operator configs:")
                for file in sorted(existing):
                    print(f"  {file}")
                # Also check for key files
                keys_dir = config_dir / "keys"
                if keys_dir.exists():
                    key_files = list(keys_dir.glob("op_*.key"))
                    if key_files:
                        print("\nExisting SSH keys:")
                        for key_file in sorted(key_files):
                            print(f"  {key_file}")
            else:
                print("No existing operator configs found.")
        else:
            print(f"Directory {config_dir} does not exist.")
        return
    if args.operator:
        # Single operator generation
        config = generator.generate_config(args.operator, args.mnemonic)
        file_path = generator.save_config(config, args.operator, args.output_dir, args.generate_keys)
        print(f"Generated operator {args.operator} config: {file_path}")

    elif args.batch_start is not None and args.batch_end is not None:
        # Batch generation
        if args.batch_start > args.batch_end:
            print("Error: batch-start must be <= batch-end")
            return

        generated = generator.generate_batch(args.batch_start, args.batch_end, args.output_dir, None, args.generate_keys)
        print(f"Generated {len(generated)} operator configs from {args.batch_start} to {args.batch_end}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()