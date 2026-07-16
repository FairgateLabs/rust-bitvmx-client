use bitcoin::Witness;
use key_manager::winternitz::{self, WinternitzSignature, WinternitzType};

use crate::errors::BitVMXError;

pub fn decode_witness(
    winternitz_message_sizes: Vec<usize>,
    winternitz_type: WinternitzType,
    witness: Witness,
) -> Result<Vec<WinternitzSignature>, BitVMXError> {
    let mut signatures = vec![];

    let mut iter = witness.iter();
    for message_size in winternitz_message_sizes.iter() {
        let message_digits_len = winternitz::message_digits_length(*message_size);
        let checksum_digits_len = winternitz::checksum_length(message_digits_len);
        let winternitz_signature_size = message_digits_len + checksum_digits_len;

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
                // Witness ran out of elements before completing the signature
                return Err(BitVMXError::InvalidWitness(witness.clone()));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn signature_digits_len(message_size: usize) -> usize {
        let message_digits_len = winternitz::message_digits_length(message_size);
        message_digits_len + winternitz::checksum_length(message_digits_len)
    }

    fn dummy_hashes_and_digits(count: usize, hash_size: usize) -> (Vec<Vec<u8>>, Vec<u8>) {
        let hashes = (0..count).map(|i| vec![i as u8 + 1; hash_size]).collect();
        let digits = (0..count).map(|i| (i % 16) as u8).collect();
        (hashes, digits)
    }

    fn build_witness(hashes: &[Vec<u8>], digits: &[u8]) -> Witness {
        let mut witness = Witness::new();
        for (hash, digit) in hashes.iter().zip(digits.iter()) {
            witness.push(hash);
            witness.push([*digit]);
        }
        witness
    }

    #[test]
    fn test_decode_single_message_hash160() {
        let message_size = 1;
        let digits_len = signature_digits_len(message_size);
        let (hashes, digits) = dummy_hashes_and_digits(digits_len, 20);
        let witness = build_witness(&hashes, &digits);

        let signatures =
            decode_witness(vec![message_size], WinternitzType::HASH160, witness).unwrap();

        assert_eq!(signatures.len(), 1);
        assert_eq!(signatures[0].to_hashes(), hashes);
        assert_eq!(signatures[0].checksummed_message_digits(), digits);
        assert_eq!(
            signatures[0].message_length(),
            winternitz::message_digits_length(message_size)
        );
    }

    #[test]
    fn test_decode_single_message_sha256() {
        let message_size = 4;
        let digits_len = signature_digits_len(message_size);
        let (hashes, digits) = dummy_hashes_and_digits(digits_len, 32);
        let witness = build_witness(&hashes, &digits);

        let signatures =
            decode_witness(vec![message_size], WinternitzType::SHA256, witness).unwrap();

        assert_eq!(signatures.len(), 1);
        assert_eq!(signatures[0].to_hashes(), hashes);
        assert_eq!(signatures[0].checksummed_message_digits(), digits);
    }

    #[test]
    fn test_decode_multiple_messages() {
        let message_sizes = vec![1, 2];
        let mut witness = Witness::new();
        let mut expected = vec![];

        for (i, message_size) in message_sizes.iter().enumerate() {
            let digits_len = signature_digits_len(*message_size);
            let (hashes, digits) = dummy_hashes_and_digits(digits_len, 20);
            for (hash, digit) in hashes.iter().zip(digits.iter()) {
                witness.push(hash);
                witness.push([*digit]);
            }
            expected.push((hashes, digits, i));
        }

        let signatures = decode_witness(message_sizes, WinternitzType::HASH160, witness).unwrap();

        assert_eq!(signatures.len(), 2);
        for (signature, (hashes, digits, _)) in signatures.iter().zip(expected.iter()) {
            assert_eq!(&signature.to_hashes(), hashes);
            assert_eq!(&signature.checksummed_message_digits(), digits);
        }
    }

    #[test]
    fn test_decode_empty_digit_defaults_to_zero() {
        let message_size = 1;
        let digits_len = signature_digits_len(message_size);
        let (hashes, _) = dummy_hashes_and_digits(digits_len, 20);

        // Push empty digit elements: decoder must treat them as digit 0
        let mut witness = Witness::new();
        for hash in hashes.iter() {
            witness.push(hash);
            witness.push([]);
        }

        let signatures =
            decode_witness(vec![message_size], WinternitzType::HASH160, witness).unwrap();

        assert_eq!(signatures.len(), 1);
        assert_eq!(
            signatures[0].checksummed_message_digits(),
            vec![0u8; digits_len]
        );
    }

    #[test]
    fn test_decode_wrong_hash_size_fails() {
        let message_size = 1;
        let digits_len = signature_digits_len(message_size);
        // 20-byte hashes are not valid for SHA256 (expects 32-byte hashes)
        let (hashes, digits) = dummy_hashes_and_digits(digits_len, 20);
        let witness = build_witness(&hashes, &digits);

        let result = decode_witness(vec![message_size], WinternitzType::SHA256, witness);

        assert!(matches!(result, Err(BitVMXError::WinternitzError(_))));
    }

    #[test]
    fn test_decode_empty_witness_fails() {
        let result = decode_witness(vec![1], WinternitzType::HASH160, Witness::new());

        assert!(matches!(result, Err(BitVMXError::InvalidWitness(_))));
    }

    #[test]
    fn test_decode_truncated_witness_fails() {
        let message_size = 1;
        let digits_len = signature_digits_len(message_size);
        let (hashes, digits) = dummy_hashes_and_digits(digits_len, 20);
        // Drop the last (hash, digit) pair
        let witness = build_witness(&hashes[..digits_len - 1], &digits[..digits_len - 1]);

        let result = decode_witness(vec![message_size], WinternitzType::HASH160, witness);

        assert!(matches!(result, Err(BitVMXError::InvalidWitness(_))));
    }
}
