// ─────────────────────────────────────────────────────────────
// node/src/round1.rs — Alg.04 — Déchiffrement KEA de Eres → MatchedPos
//
// Exécuté UNIQUEMENT par l'initiateur (détient sk + psy).
// paillier_kea_decrypt VÉRIFIE l'intégrité (img_verif : ψ·μ0 == μ1) avant de
// renvoyer le clair — c'est le contrôle CCA1 sur le résultat homomorphe.
// ─────────────────────────────────────────────────────────────

use num_bigint::BigUint;
use num_traits::Zero;

use dpeg_shared::paillier_kea::paillier_kea_decrypt;
use dpeg_shared::paillier::p_keygen::p_keygen::{PublicKey, SecretKey};
use dpeg_shared::crypto_error::crypto_error::CryptoError;
use dpeg_shared::exactmatch::types::Edb;

/// Alg.04 — déchiffrement KEA de Eres → positions communes.
/// MatchedPos = { i | Dec(Eres[i]) == 0 }. Toute case dont la vérification
/// d'image KEA échoue fait remonter CryptoError::KeaImVerFailed.
pub fn decrypt_round1(
    e:   &Edb,
    pk:  &PublicKey,
    sk:  &SecretKey,
    psy: &BigUint,
) -> Result<Vec<usize>, CryptoError> {
    let mut acc = Vec::new();
    for (i, ct) in e.iter().enumerate() {
        let x = paillier_kea_decrypt(pk, sk, psy, ct)?; // vérifie + déchiffre
        if x.is_zero() {
            acc.push(i);
        }
    }
    Ok(acc)
}
