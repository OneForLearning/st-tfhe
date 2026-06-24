// ─────────────────────────────────────────────────────────────
// round2.rs (Serveur) — Alg.07 — Calcul de Echeck
//
// Pour chaque paire (c1 H1, c2 H2) à la même position :
//   diff      = HE_Sub(c1, c2)        = Enc(encode(id1) - encode(id2))
//   α_j       = random_nonzero(pk.n)  (scalaire secret du Serveur)
//   Echeck[j] = HE_SMul(diff, α_j)    = Enc(α_j × diff)
//
// Propriété : α_j × 0 = 0  →  Dec(Echeck[j]) = 0 ssi id1 = id2.
// H1 ne peut pas inverser α_j (il ne le connaît pas).
// Les labels (INS en clair) ne transitent jamais par le Serveur :
// H1 les conserve localement et les réassocie par index à la réception de Echeck.
// ─────────────────────────────────────────────────────────────

use std::collections::HashMap;
use dpeg_shared::exactmatch::types::KeaCt;
use dpeg_shared::paillier::p_keygen::p_keygen::PublicKey;
use dpeg_shared::crypto_error::crypto_error::CryptoError;
use dpeg_shared::exactmatch::crypto_utils::random_nonzero;
use crate::exactmatch::hom_ops::{he_sub, he_smul};


/// Alg.07 — Serveur : calcul de Echeck via HE_Sub + HE_SMul(α_j).
///
/// Le serveur ne reçoit et ne renvoie que des chiffrés : les labels (INS en clair)
/// restent chez H1 et sont réassociés par index à la réception de Echeck.
pub fn eval_round2(
    b1: &HashMap<usize, Vec<KeaCt>>,
    b2: &HashMap<usize, Vec<KeaCt>>,
    pk: &PublicKey,
) -> Result<Vec<KeaCt>, CryptoError> {
    let mut res = Vec::new();
    // Positions triées — alignement strict avec h1_labels (côté H1).
    // Sans ce tri, l'itération HashMap est non déterministe (seed aléatoire),
    // ce qui désaligne Echeck[j] et labels[j] → perte de vrais positifs.
    let mut positions: Vec<usize> = b1.keys().copied().collect();
    positions.sort();
    for p in positions {
        let l1 = &b1[&p];
        if let Some(l2) = b2.get(&p) {
            for c1 in l1 {
                for c2 in l2 {
                    let d = he_sub(c1, c2, pk)?;
                    let a = random_nonzero(&pk.n)?;
                    res.push(he_smul(&d, &a, pk));
                }
            }
        }
    }
    Ok(res)
}