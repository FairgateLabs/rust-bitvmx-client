use bitcoin::Witness;
use key_manager::winternitz::{self, WinternitzSignature, WinternitzType};

use crate::errors::BitVMXError;

pub fn decode_witness(
    winternitz_message_sizes: Vec<usize>,
    winternitz_type: WinternitzType,
    witness: Witness,
) -> Result<Vec<WinternitzSignature>, BitVMXError> {
    let mut signatures = vec![];

    for message_size in winternitz_message_sizes.iter() {
        let message_digits_len = winternitz::message_digits_length(*message_size);
        let checksum_digits_len = winternitz::checksum_length(message_digits_len);
        let winternitz_signature_size = message_digits_len + checksum_digits_len;

        let mut iter = witness.iter();

        let mut processed = 0;
        let mut hashes = vec![];
        let mut digits = vec![];

        while processed < winternitz_signature_size * 2 {
            // Retrieve hash and digit at a time and ensure not to exceed the chunk size
            if let (Some(hash), Some(mut digit)) = (iter.next(), iter.next()) {
                if digit.is_empty() {
                    digit = &[0];
                }

                hashes.extend_from_slice(hash);
                digits.extend_from_slice(digit);
                processed += 2;
            } else {
                break;
            }
        }

        let signature = WinternitzSignature::from_hashes_and_digits(
            hashes.as_slice(),
            digits.as_slice(),
            message_digits_len,
            winternitz_type,
        )?;

        signatures.push(signature);
    }

    Ok(signatures)
}
