use num_bigint::BigUint;
use num_traits::{One, Zero};
use crate::paillier::p_keygen::p_keygen::{SecretKey, PublicKey};
use crate::paillier::rug_bridge::modpow;
use crate::crypto_error::crypto_error::CryptoError;

// ---------------------------------------------------------------------------
// Déchiffrement Paillier avec CRT (Chinese Remainder Theorem)
//
// Référence : Pascal Paillier, EUROCRYPT 1999, section 7.
//
// Au lieu de c^λ mod n² (module 4096 bits, exposant 2048 bits), on calcule :
//   m_p = L_p(c^(p-1) mod p²) · hp mod p
//   m_q = L_q(c^(q-1) mod q²) · hq mod q
//   m   = CRT(m_p, m_q) = m_q + q · ((m_p - m_q) · q_inv_p mod p)
//
// Deux exponentiations mod p² et q² (2048 bits) au lieu d'une mod n² (4096).
// Gain ≈ ×3-4 sur le déchiffrement.
//
// SÉCURITÉ : résultat mathématiquement identique au déchiffrement standard.
// Les paramètres CRT dérivent de p,q (confidentialité = factorisation de n).
// ---------------------------------------------------------------------------
pub fn p_decrypt(c: &BigUint, pk: &PublicKey, sk: &SecretKey)
    -> Result<BigUint, CryptoError>
{
    if c > &pk.n_squared {
        return Err(CryptoError::CiphertextOutOfRange);
    }

    let p_minus_1 = &sk.p - BigUint::one();
    let q_minus_1 = &sk.q - BigUint::one();

    // ── Branche p : m_p = L_p(c^(p-1) mod p²) · hp mod p ────────────────────
    let cp = modpow(c, &p_minus_1, &sk.p_squared);   // exposant ~1024b, module 2048b
    let lp = (&cp - BigUint::one()) / &sk.p;          // L_p(x) = (x-1)/p
    let m_p = (&lp * &sk.hp) % &sk.p;

    // ── Branche q : m_q = L_q(c^(q-1) mod q²) · hq mod q ────────────────────
    let cq = modpow(c, &q_minus_1, &sk.q_squared);
    let lq = (&cq - BigUint::one()) / &sk.q;          // L_q(x) = (x-1)/q
    let m_q = (&lq * &sk.hq) % &sk.q;

    // ── Recombinaison CRT : m = m_q + q · ((m_p - m_q) · q_inv_p mod p) ─────
    // Soustraction modulaire sûre (m_p - m_q peut être négatif).
    let diff = if m_p >= m_q {
        (&m_p - &m_q) % &sk.p
    } else {
        let d = (&m_q - &m_p) % &sk.p;
        if d.is_zero() { BigUint::zero() } else { &sk.p - d }
    };
    let t = (&diff * &sk.q_inv_p) % &sk.p;
    let m = &m_q + &sk.q * &t;

    Ok(m % &pk.n)
}
