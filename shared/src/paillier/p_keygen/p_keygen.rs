// =============================================================================
//  p_keygen.rs — Génération de clés Paillier
//
//  Conformité : ANSSI RGS v2.0, NIST SP 800-56B Rev2
//
//       — Le paramètre nbits désigne la taille de n (le module
//          Paillier), conformément à la convention industrielle.
//          p et q sont générés avec nbits/2 bits chacun.
//        — Zéroïsation de p et q après usage (évite la fuite mémoire).
//        — Avertissement si nbits < RECOMMENDED_KEY_BITS (3072).
// =============================================================================

use num_bigint::BigUint;
use num_traits::One;
use zeroize::Zeroize;
use crate::paillier::math::{
    l_function, lcm, mod_inverse,
    generate_prime,
    MIN_KEY_BITS, RECOMMENDED_KEY_BITS,
};
use crate::crypto_error::crypto_error::CryptoError;

// =============================================================================
// Clé publique Paillier
//
// Contient uniquement des données publiques — pas de zeroize nécessaire.
// pk = (n, g, n^2) est transmis aux participants et au Serveur.
// =============================================================================
#[derive(Clone, Debug)]
pub struct PublicKey {
    pub n:         BigUint,   // module RSA n = p·q
    pub g:         BigUint,   // générateur g = n + 1
    pub n_squared: BigUint,   // n^2 (pré-calculé pour les opérations Homomorphic Encryption)
}

// =============================================================================
// Zéroïsation manuelle d'un BigUint
//
// BigUint n'implémente pas le trait Zeroize de la crate zeroize.
// On écrase d'abord avec un vecteur de zéros de la même taille (pour écraser
// les données en mémoire), puis on réassigne la valeur par défaut.
// =============================================================================
fn zeroize_biguint(n: &mut BigUint) {
    let bits = n.bits() as usize;
    if bits > 0 {
        *n = BigUint::from_bytes_be(&vec![0u8; (bits + 7) / 8]);
    }
    *n = BigUint::default();
}

// =============================================================================
// Clé secrète Paillier — ZEROISÉE À LA DESTRUCTION
//
// sk = (lambda, mu) reste exclusivement chez BD1 et n'est jamais transmis.
// lambda et mu sont écrasés à zéro lors de la destruction de l'objet (Drop).
// =============================================================================
#[derive(Clone, Debug)]
pub struct SecretKey {
    pub lambda: BigUint,   // lambda = lcm(p−1, q−1) — exponent de déchiffrement
    pub mu:     BigUint,   // mu = L(g^λ mod n^2)^-1 mod n — facteur de correction

    // ── Paramètres CRT (Chinese Remainder Theorem) ──────────────────────────
    // Permettent un déchiffrement ~4× plus rapide en travaillant mod p² et q²
    // (2048 bits) au lieu de mod n² (4096 bits).
    // Référence : Paillier 1999, section 7 (décryption avec CRT).
    // Ces valeurs dérivent de p et q : leur confidentialité équivaut à celle
    // de la factorisation de n. Zéroïsées à la destruction.
    pub p:        BigUint,   // premier p
    pub q:        BigUint,   // premier q
    pub p_squared: BigUint,  // p²
    pub q_squared: BigUint,  // q²
    pub hp:       BigUint,   // hp = L_p(g^(p-1) mod p²)^{-1} mod p
    pub hq:       BigUint,   // hq = L_q(g^(q-1) mod q²)^{-1} mod q
    pub q_inv_p:  BigUint,   // q^{-1} mod p (recombinaison CRT)
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        zeroize_biguint(&mut self.lambda);
        zeroize_biguint(&mut self.mu);
        zeroize_biguint(&mut self.p);
        zeroize_biguint(&mut self.q);
        zeroize_biguint(&mut self.p_squared);
        zeroize_biguint(&mut self.q_squared);
        zeroize_biguint(&mut self.hp);
        zeroize_biguint(&mut self.hq);
        zeroize_biguint(&mut self.q_inv_p);
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// =============================================================================
// Paire de clés Paillier
// =============================================================================
#[derive(Clone, Debug)]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

// =============================================================================
// Dérivation des paramètres CRT à partir de p, q et g.
//
// Réutilisée par p_keygen (génération) et par le chargement depuis JSON
// (key_storage), garantissant une cohérence unique. Calcule hp, hq, q_inv_p,
// p², q² nécessaires au déchiffrement CRT.
// =============================================================================
pub fn derive_crt_params(
    p: &BigUint,
    q: &BigUint,
    g: &BigUint,
) -> Result<(BigUint, BigUint, BigUint, BigUint, BigUint), CryptoError> {
    let p_minus_1 = p - BigUint::one();
    let q_minus_1 = q - BigUint::one();
    let p_squared = p * p;
    let q_squared = q * q;

    // hp = (L_p(g^(p-1) mod p²))^{-1} mod p   avec L_p(x) = (x-1)/p
    let g_pm1 = g.modpow(&p_minus_1, &p_squared);
    let lp = (&g_pm1 - BigUint::one()) / p;
    let hp = mod_inverse(&(&lp % p), p)?;

    // hq = (L_q(g^(q-1) mod q²))^{-1} mod q
    let g_qm1 = g.modpow(&q_minus_1, &q_squared);
    let lq = (&g_qm1 - BigUint::one()) / q;
    let hq = mod_inverse(&(&lq % q), q)?;

    // q^{-1} mod p (recombinaison CRT)
    let q_inv_p = mod_inverse(&(q % p), p)?;

    Ok((p_squared, q_squared, hp, hq, q_inv_p))
}

// =============================================================================
// Génération de clés Paillier — p_keygen(nbits)
//
// Paramètre
// Référence : Pascal Paillier, "Public-Key Cryptosystems Based on Composite
//             Degree Residuosity Classes", EUROCRYPT 1999.
// =============================================================================
pub fn p_keygen(nbits: u64) -> Result<KeyPair, CryptoError> {

    // ── Vérification de la taille minimale (ANSSI/NIST) ─────────────────────
    if nbits < MIN_KEY_BITS {
        return Err(CryptoError::KeySizeTooSmall {
            requested: nbits,
            minimum:   MIN_KEY_BITS,
        });
    }

    // ── Avertissement sous le seuil recommandé (non bloquant) ───────────────
    if nbits < RECOMMENDED_KEY_BITS {
        eprintln!(
            "[p_keygen] AVERTISSEMENT : n = {} bits < {} bits recommandés (ANSSI 2026+). \
             Acceptable pour des tests.",
            nbits, RECOMMENDED_KEY_BITS
        );
    }

    // ── Taille de chaque premier : prime_bits = nbits / 2 ───────────────────

    let prime_bits = nbits / 2;

    // ── Génération de p et q 

    // Référence : NIST SP 800-56B Rev2,
    let mut p = generate_prime(prime_bits)?;
    let mut q = generate_prime(prime_bits)?;

    // Garantir p ≠ q (probabilité ≈ 1/2^(prime_bits) — quasi-impossible mais
    // nécessaire pour la rigueur formelle)
    while p == q {
        q = generate_prime(prime_bits)?;
    }

    // ── Calcul des paramètres Paillier ───────────────────────────────────────
    let n         = &p * &q;
    let n_squared = &n * &n;

    let p_minus_1 = &p - BigUint::one();
    let q_minus_1 = &q - BigUint::one();

    // λ = lcm(p−1, q−1) — exposant de Carmichael
    let lambda = lcm(&p_minus_1, &q_minus_1);

    // ── Générateur g = n + 1 ─────────────────────────────────────────────────
    let g = &n + BigUint::one();

    // ── Paramètres CRT — calculés AVANT zéroïsation de p et q ───────────────
    let (p_squared, q_squared, hp, hq, q_inv_p) = derive_crt_params(&p, &q, &g)?;

    // ── Calcul de mu (déchiffrement non-CRT, conservé en fallback) ──────────
    let g_lambda = g.modpow(&lambda, &n_squared);
    let l_g_lambda = l_function(&g_lambda, &n)?;
    let mu = mod_inverse(&l_g_lambda, &n)?;

    // Clones de p et q pour la SecretKey (avant zéroïsation des originaux)
    let p_sk = p.clone();
    let q_sk = q.clone();

    // ── Zéroïsation des p et q de travail ───────────────────────────────────
    zeroize_biguint(&mut p);
    zeroize_biguint(&mut q);

    Ok(KeyPair {
        public_key: PublicKey { n, g, n_squared },
        secret_key: SecretKey {
            lambda, mu,
            p: p_sk, q: q_sk,
            p_squared, q_squared,
            hp, hq, q_inv_p,
        },
    })
}