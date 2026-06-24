// ─────────────────────────────────────────────────────────────
// round1.rs (Serveur) — Alg.03 — HE_Add case à case
//
// Le Serveur reçoit EDB1 et EDB2 (chiffrés sous pk de H1),
// calcule Eres = EDB1 + EDB2 homomorphiquement, et renvoie
// Eres à H1 pour déchiffrement.
// ─────────────────────────────────────────────────────────────

use dpeg_shared::paillier::p_keygen::p_keygen::PublicKey;
use dpeg_shared::crypto_error::crypto_error::CryptoError;
use dpeg_shared::exactmatch::types::Edb;

use crate::exactmatch::hom_ops::he_add;

/// Alg.03 — Serveur : HE_Add case à case.
///
/// Eres[i] = HE_Add(EDB1[i], EDB2[i]) = Enc(EDB1_plain[i] + EDB2_plain[i])
///
/// Propriété : si les deux hôpitaux ont un identifiant à la position i,
/// EDB1[i] = EDB2[i] = Enc(0) -> Eres[i] = Enc(0+0) = Enc(0).
///
/// Le Serveur ne peut pas distinguer Enc(0) de Enc(aléatoire) sans sk.
pub fn eval_round1(
    e1: &Edb,
    e2: &Edb,
    pk: &PublicKey,
) -> Result<Edb, CryptoError> {
    if e1.len() != e2.len() {
        return Err(CryptoError::EdbSizeMismatch {
            len1: e1.len(),
            len2: e2.len(),
        });
    }
    Ok(e1.iter().zip(e2).map(|(a, b)| he_add(a, b, pk)).collect())
}
