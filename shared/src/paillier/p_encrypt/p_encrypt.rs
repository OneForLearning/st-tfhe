use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use rand_core::OsRng;
use crate::paillier::p_keygen::PublicKey;
use crate::paillier::math::gcd;
use crate::paillier::rug_bridge::modpow;
use crate::crypto_error::crypto_error::CryptoError;

// ---------------------------------------------------------------------------
// Chiffrement Paillier : c = g^m * r^n  mod n^2
//
// OPTIMISATION (g = n+1) :
//   g^m = (1+n)^m ≡ 1 + m·n (mod n²) par le binôme de Newton.
//   On remplace l'exponentiation g^m par une multiplication (1 + m·n).
//   Seul r^n reste une exponentiation (via GMP). Sécurité identique.
// ---------------------------------------------------------------------------
pub fn p_encrypt(m: &BigUint, pk: &PublicKey) -> Result<BigUint, CryptoError> {
    if m > &pk.n {
        return Err(CryptoError::MessageOutOfRange);
    }

    let mut rng = OsRng;

    // Choisit r dans Z*_n : gcd(r, n) = 1
    let r = loop {
        let candidate = rng.gen_biguint_range(&One::one(), &pk.n);
        if gcd(&candidate, &pk.n) == BigUint::one() {
            break candidate;
        }
    };

    // g^m mod n² = (1 + m·n) mod n²  (identité valable ssi g = n+1)
    let g_m = (m * &pk.n + BigUint::one()) % &pk.n_squared;
    // r^n mod n²  — exponentiation via GMP (le coût principal)
    let r_n = modpow(&r, &pk.n, &pk.n_squared);
    let c   = (&g_m * &r_n) % &pk.n_squared;

    Ok(c)
}
