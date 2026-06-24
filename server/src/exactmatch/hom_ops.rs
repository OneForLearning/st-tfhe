// ─────────────────────────────────────────────────────────────
// hom_ops.rs (Serveur) — Opérations homomorphes KEA (Paillier P², CCA1)
//
// Un chiffré KEA est une PAIRE (Enc(m), Enc(ψ·m)). Les opérations s'appliquent
// COMPOSANTE PAR COMPOSANTE. Comme la relation ψ·m est linéaire, elle est
// préservée :
//   he_add  : (Enc(a),Enc(ψa))·(Enc(b),Enc(ψb)) = (Enc(a+b), Enc(ψ(a+b)))
//   he_sub  : idem avec l'inverse                 = (Enc(a-b), Enc(ψ(a-b)))
//   he_smul : (Enc(m),Enc(ψm))^α                  = (Enc(αm),  Enc(ψ(αm)))
// → le résultat reste un chiffré KEA valide, vérifiable par img_verif.
// ─────────────────────────────────────────────────────────────

use num_bigint::BigUint;

use dpeg_shared::paillier::p_keygen::p_keygen::PublicKey;
use dpeg_shared::crypto_error::crypto_error::CryptoError;
use dpeg_shared::exactmatch::crypto_utils::mod_inverse;
use dpeg_shared::exactmatch::types::KeaCt;

/// HE_Add(c1, c2) = produit composante par composante mod n².
/// HE_Add(KEA(a), KEA(b)) = KEA(a + b mod n)
pub fn he_add(c1: &KeaCt, c2: &KeaCt, pk: &PublicKey) -> KeaCt {
    (
        (&c1.0 * &c2.0) % &pk.n_squared,
        (&c1.1 * &c2.1) % &pk.n_squared,
    )
}

/// HE_Sub(c1, c2) = c1 × c2^{-1} composante par composante mod n².
/// HE_Sub(KEA(a), KEA(b)) = KEA(a - b mod n)
pub fn he_sub(c1: &KeaCt, c2: &KeaCt, pk: &PublicKey) -> Result<KeaCt, CryptoError> {
    let inv0 = mod_inverse(&c2.0, &pk.n_squared)?;
    let inv1 = mod_inverse(&c2.1, &pk.n_squared)?;
    Ok((
        (&c1.0 * inv0) % &pk.n_squared,
        (&c1.1 * inv1) % &pk.n_squared,
    ))
}

/// HE_SMul(c, α) = c^α composante par composante mod n².
/// HE_SMul(KEA(m), α) = KEA(α·m mod n)
pub fn he_smul(c: &KeaCt, alpha: &BigUint, pk: &PublicKey) -> KeaCt {
    (
        smul_component(&c.0, alpha, &pk.n_squared),
        smul_component(&c.1, alpha, &pk.n_squared),
    )
}

/// c^α mod n² via rug (GMP).
fn smul_component(c: &BigUint, alpha: &BigUint, n_squared: &BigUint) -> BigUint {
    use rug::integer::Order;
    use rug::Integer;

    let c_rug  = Integer::from_digits(&c.to_bytes_be(), Order::MsfBe);
    let a_rug  = Integer::from_digits(&alpha.to_bytes_be(), Order::MsfBe);
    let n2_rug = Integer::from_digits(&n_squared.to_bytes_be(), Order::MsfBe);

    let result = c_rug.pow_mod(&a_rug, &n2_rug)
        .expect("he_smul: n_squared doit être > 0");

    let bytes: Vec<u8> = result.to_digits::<u8>(Order::MsfBe);
    if bytes.is_empty() { BigUint::from(0u32) } else { BigUint::from_bytes_be(&bytes) }
}
