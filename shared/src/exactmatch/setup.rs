// ─────────────────────────────────────────────────────────────
// setup.rs — Setup du protocole PSI
//
// Alg.01 : génération de la paire de clés Paillier
// compute_n : calcul de la taille de la table EDB
// ─────────────────────────────────────────────────────────────

use crate::paillier::p_keygen::p_keygen::{p_keygen, PublicKey, SecretKey};
use crate::crypto_error::crypto_error::CryptoError;

/// Alg.01 — Génération de la paire de clés Paillier.
///
/// Génère (pk, sk) avec un module n de 'bits' bits.
/// pk = (n, g, n^2) -> transmis à H2 et au Serveur.
/// sk = (lambda, mu)     -> conservé exclusivement chez H1.
pub fn alg01_setup(bits: u64) -> Result<(PublicKey, SecretKey), CryptoError> {
    println!("── [Alg.01] KeyGen Paillier {} bits …", bits);
    use std::time::Instant;
    let t  = Instant::now();
    let kp = p_keygen(bits)
        .map_err(|e| CryptoError::KeyGenFailed(e.to_string()))?;
    println!(
        "── [Alg.01] n = {} bits — {:.3?}",
        kp.public_key.n.bits(), t.elapsed()
    );
    println!("── [Alg.01] pk → H2 et Serveur | sk → H1 uniquement");
    Ok((kp.public_key, kp.secret_key))
}

/// Calcule la taille N de la table EDB.
///
/// N = next_pow2(beta × max(|H1|, |H2|))
///
/// Garanties :
/// - beta ≥ 1 (Err::InvalidParam sinon)
/// - D1 ou D2 non vide (Err::EmptyDatabase sinon)
/// - Pas de débordement usize (Err::NOverflow sinon)
pub fn compute_n(d1: usize, d2: usize, beta: f64) -> Result<usize, CryptoError> {
    // Borne inférieure : beta >= 1/10
    if beta < 0.1 - f64::EPSILON {
        return Err(CryptoError::InvalidParam(
            "beta doit être >= 1/10 (0.1)".to_string()
        ));
    }
    if d1 == 0 && d2 == 0 {
        return Err(CryptoError::EmptyDatabase { which: "D1 et D2" });
    }
    let max = d1.max(d2);
    let product_f = beta * max as f64;
    if product_f > (usize::MAX / 2) as f64 {
        return Err(CryptoError::NOverflow);
    }
    let product = product_f.ceil() as usize;
    if product > usize::MAX / 2 {
        return Err(CryptoError::NOverflow);
    }
    let n = product.next_power_of_two();
    println!(
        "── [Setup] N = next_pow2(ceil({} × max({},{}))) = {}",
        beta, d1, d2, n
    );
    Ok(n)
}
