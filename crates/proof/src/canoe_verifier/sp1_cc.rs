use crate::canoe_verifier::errors::HokuleaCanoeVerificationError;
use crate::canoe_verifier::CanoeVerifier;
use crate::cert_validity::CertValidity;
use alloc::vec::Vec;
use eigenda_cert::AltDACommitment;

use tracing::{info, warn};

#[derive(Clone)]
pub struct CanoeSp1CCVerifier {}

impl CanoeVerifier for CanoeSp1CCVerifier {
    // some variable is unused, because when sp1-cc verifier is not configured in zkVM mode, all tests
    // are skipped because sp1 cannot take sp1-sdk as dependency
    #[allow(unused_variables)]
    fn validate_cert_receipt(
        &self,
        cert_validity_pair: Vec<(AltDACommitment, CertValidity)>,
        canoe_proof_bytes: Option<Vec<u8>>,
    ) -> Result<(), HokuleaCanoeVerificationError> {
        info!("using CanoeSp1CCVerifier");

        cfg_if::cfg_if! {
            if #[cfg(target_os = "zkvm")] {
                use sha2::{Digest, Sha256};
                use sp1_lib::verify::verify_sp1_proof;
                use sp1_verifier::decode_sp1_vkey_hash;
                use crate::canoe_verifier::to_journals_bytes;

                let journals_bytes = to_journals_bytes(cert_validity_pair);

                // if not in dev mode, the receipt should be empty
                if canoe_proof_bytes.is_some() {
                    // Sp1 doc https://github.com/succinctlabs/sp1/blob/a1d873f10c32f5065de120d555cfb53de4003da3/examples/aggregation/script/src/main.rs#L75
                    warn!("sp1-cc verification within zkvm requires proof being provided via zkVM stdin");
                }
                // used within zkVM
                let public_values_digest = Sha256::digest(journals_bytes);
                // TODO(fakedev9999): get vkey from ELF, this hardcoded value is from elf built with sp1 v5.2.1.
                let vk_digest: [u32; 8] = [1396757925, 1924634056, 1379667269, 1057574788, 1146178491, 1824078624, 1633187330, 412400592];

                // the function will panic if the proof is incorrect
                // https://github.com/succinctlabs/sp1/blob/011d2c64808301878e6f0375c3596b3e22e53949/crates/zkvm/lib/src/verify.rs#L3
                verify_sp1_proof(&vk_digest, &public_values_digest.into());
            } else {
                warn!("Skipping sp1CC proof verification in native mode outside of zkVM, because sp1 cannot take sp1-sdk as dependency which is needed for verification in the native mode");
            }
        }
        Ok(())
    }
}

/// Parse vkey hash from cargo prove vkey output to [u32; 8] for verify_sp1_proof
fn parse_vkey_hash_to_u32_array(vkey_hash_hex: &str) -> [u32; 8] {
    // Remove 0x prefix if present
    let hex_str = vkey_hash_hex.strip_prefix("0x").unwrap_or(vkey_hash_hex);

    // Decode hex to bytes
    let bytes = hex::decode(hex_str).expect("Invalid hex string");
    assert_eq!(bytes.len(), 32, "VKey hash must be 32 bytes");

    // Convert bytes to [u32; 8] in little-endian format (BabyBear field elements)
    let mut result = [0u32; 8];
    for (i, chunk) in bytes.chunks(4).enumerate() {
        // Convert each 4-byte chunk to u32 in little-endian
        result[i] = u32::from_le_bytes(chunk.try_into().unwrap());
    }

    result
}
