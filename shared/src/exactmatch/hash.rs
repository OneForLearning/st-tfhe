// ─────────────────────────────────────────────────────────────
// hash.rs — Hachage et encodage des clés de correspondance PSI
//
// Deux fonctions distinctes avec domaines de séparation :
//   hash_pos   -> position dans la table EDB (Round 1)
//   encode_id  -> encodage pour comparaison chiffrée (Round 2)
//
// Entrée : MatchKey = [u8; 32] (SHA-256 du composite canonique, cf. canonical.rs).
// Les domaines garantissent que hash_pos et encode_id ne partagent jamais le
// même espace de sortie pour une même clé.
// ─────────────────────────────────────────────────────────────

use num_bigint::BigUint;
use sha2::{Sha256, Digest};

use crate::paillier::p_keygen::p_keygen::PublicKey;
use crate::crypto_error::crypto_error::CryptoError;
use super::types::{HASH_DOMAIN, ENCODE_DOMAIN, MatchKey};
use super::canonical::key_hex;

/// h(key) = SHA-256(HASH_DOMAIN || key) mod N  →  position dans l'EDB.
pub fn hash_pos(key: &MatchKey, n: usize) -> usize {
    let mut h = Sha256::new();
    h.update(HASH_DOMAIN);
    h.update(&key[..]);
    let digest = BigUint::from_bytes_be(&h.finalize());
    let rem    = digest % BigUint::from(n);
    rem.to_u64_digits().first().copied().unwrap_or(0) as usize
}

/// encode_id(key) = SHA-256(ENCODE_DOMAIN || key)  →  valeur pour comparaison.
/// SHA-256 produit 256 bits < pk.n (2048 bits) : v < pk.n est toujours vrai.
pub fn encode_id(key: &MatchKey, pk: &PublicKey) -> Result<BigUint, CryptoError> {
    let mut h = Sha256::new();
    h.update(ENCODE_DOMAIN);
    h.update(&key[..]);
    let v = BigUint::from_bytes_be(&h.finalize());
    if v >= pk.n {
        return Err(CryptoError::EncodeOutOfRange { id: key_hex(key) });
    }
    Ok(v)
}
