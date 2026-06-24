// ─────────────────────────────────────────────────────────────
// node/src/round2.rs — Round 2, les DEUX rôles (chiffrement KEA)
//
//   INITIATEUR  : h1_buckets (chiffrés KEA) + h1_labels (clés locales)
//                 + decrypt_round2 (déchiffre+vérifie Echeck → clés communes)
//   PARTICIPANT : h2_buckets  (chiffrés KEA SANS labels)
//
// Le chiffrement utilise paillier_kea_encrypt(message, pk, ct_delta) → paire
// (Enc(m), Enc(ψ·m)). ct_delta est PUBLIC (distribué avec pk). psy est SECRET
// (initiateur uniquement) et requis pour decrypt_round2.
// ─────────────────────────────────────────────────────────────

use num_bigint::BigUint;
use num_traits::Zero;
use std::collections::HashMap;

use dpeg_shared::paillier_kea::{paillier_kea_encrypt, paillier_kea_decrypt};
use dpeg_shared::paillier::p_keygen::p_keygen::{PublicKey, SecretKey};
use dpeg_shared::crypto_error::crypto_error::CryptoError;
use dpeg_shared::exactmatch::types::{MapLocal, MatchKey, KeaCt};
use dpeg_shared::exactmatch::hash::encode_id;

/// Alg.06 (initiateur) — Candidats chiffrés KEA de l'initiateur (sans labels).
/// `ct_delta` (public) est nécessaire au chiffrement KEA.
pub fn h1_buckets(
    map: &MapLocal,
    pos: &[usize],
    pk:  &PublicKey,
    ct_delta: &KeaCt,
) -> Result<HashMap<usize, Vec<KeaCt>>, CryptoError> {
    let mut res = HashMap::new();
    let mut sorted_pos = pos.to_vec();
    sorted_pos.sort();
    for &p in &sorted_pos {
        if let Some(keys) = map.get(&p) {
            let mut sorted: Vec<&MatchKey> = keys.iter().collect();
            sorted.sort();
            let v: Result<Vec<KeaCt>, CryptoError> = sorted.iter().map(|k| {
                let enc = encode_id(k, pk)?;
                paillier_kea_encrypt(&enc, pk, ct_delta)
            }).collect();
            res.insert(p, v?);
        }
    }
    Ok(res)
}

/// Alg.06b (initiateur) — Labels locaux (MatchKey), même ordre que eval_round2.
/// Chaque label répété `counts[p]` fois (paires c1×c2 du serveur).
pub fn h1_labels(
    map:    &MapLocal,
    pos:    &[usize],
    counts: &HashMap<usize, usize>,
) -> Vec<MatchKey> {
    let mut labels = Vec::new();
    let mut sorted_pos = pos.to_vec();
    sorted_pos.sort();
    for &p in &sorted_pos {
        if let Some(keys) = map.get(&p) {
            let n_resp = counts.get(&p).copied().unwrap_or(0);
            if n_resp == 0 { continue; }
            let mut sorted: Vec<&MatchKey> = keys.iter().collect();
            sorted.sort();
            for k in sorted {
                for _ in 0..n_resp {
                    labels.push(*k);
                }
            }
        }
    }
    labels
}

/// Alg.06 (participant) — Candidats chiffrés KEA, SANS labels.
pub fn h2_buckets(
    map: &MapLocal,
    pos: &[usize],
    pk:  &PublicKey,
    ct_delta: &KeaCt,
) -> Result<HashMap<usize, Vec<KeaCt>>, CryptoError> {
    let mut res = HashMap::new();
    let mut sorted_pos = pos.to_vec();
    sorted_pos.sort();
    for &p in &sorted_pos {
        if let Some(keys) = map.get(&p) {
            let mut sorted = keys.clone();
            sorted.sort();
            let v: Result<Vec<KeaCt>, CryptoError> = sorted.iter().map(|k| {
                let enc = encode_id(k, pk)?;
                paillier_kea_encrypt(&enc, pk, ct_delta)
            }).collect();
            res.insert(p, v?);
        }
    }
    Ok(res)
}

/// Alg.08 (initiateur) — Déchiffrement+vérification KEA de Echeck → clés communes.
/// Dec(Echeck[j]) == 0 ⟺ id1 = id2. img_verif détecte tout chiffré falsifié.
pub fn decrypt_round2(
    echeck: &[KeaCt],
    labels: &[MatchKey],
    pk:     &PublicKey,
    sk:     &SecretKey,
    psy:    &BigUint,
) -> Result<Vec<MatchKey>, CryptoError> {
    if echeck.len() != labels.len() {
        return Err(CryptoError::InvalidParam(format!(
            "decrypt_round2 : echeck.len()={} != labels.len()={}",
            echeck.len(), labels.len()
        )));
    }
    let mut result = Vec::new();
    for (ct, label) in echeck.iter().zip(labels.iter()) {
        let y = paillier_kea_decrypt(pk, sk, psy, ct)?;
        if y.is_zero() {
            result.push(*label);
        }
    }
    Ok(result)
}
