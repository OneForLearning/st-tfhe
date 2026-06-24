// ─────────────────────────────────────────────────────────────
// crypto_utils.rs — Utilitaires cryptographiques
//
// Ces fonctions sont publiques car utilisées par plusieurs crates :
//   random_nonzero -> edb.rs (shared), round2.rs (server), dpeg_py
//   mod_inverse    -> hom_ops.rs (server)
// ─────────────────────────────────────────────────────────────

use num_bigint::BigUint;
use num_traits::One;
use rand::rngs::OsRng;
use num_bigint::RandBigInt;

use crate::crypto_error::crypto_error::CryptoError;

/// Tire une valeur aléatoire dans [1, n) via le CSPRNG système (OsRng).
/// Retourne Err::InvalidParam si n ≤ 1.
pub fn random_nonzero(n: &BigUint) -> Result<BigUint, CryptoError> {
    if n <= &BigUint::one() {
        return Err(CryptoError::InvalidParam(
            "random_nonzero: n doit être > 1".to_string()
        ));
    }
    let mut rng = OsRng;
    Ok(rng.gen_biguint_range(&BigUint::one(), n))
}

/// Inverse modulaire de a mod m via GMP (rug).
/// Retourne Err::ModInverseUndefined si gcd(a, m) ≠ 1.
pub fn mod_inverse(
    a: &BigUint,
    m: &BigUint,
) -> Result<BigUint, CryptoError> {
    use crate::paillier::rug_bridge::mod_inverse_rug;
    mod_inverse_rug(a, m).ok_or(CryptoError::ModInverseUndefined)
}
