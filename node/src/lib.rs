// ============================================================================
//  node/src/lib.rs — dpeg_node : bibliothèque cryptographique du nœud hôpital
//
//  Le MÊME crate sert TOUS les hôpitaux (H1…H10). Le rôle se traduit par les
//  fonctions appelées (pas de rôle codé en dur) :
//
//    • INITIATEUR (déclenche, détient sk, obtient le résultat) :
//        prepare_csv → keygen → build_database → decrypt_round1
//        → h1_buckets + h1_labels → decrypt_round2 → write_intersection_csv
//    • PARTICIPANT (chiffre seulement, jamais sk, aucun résultat) :
//        prepare_csv → build_database → h2_buckets → counts_of
//
//  Le PSI se fait sur le HASH du composite (prénom, nom, date de naissance,
//  NSS) — voir prologue + dpeg_shared::canonical. AUCUN transport ici.
// ============================================================================

pub mod prologue;  // préparation CSV : clés, dédup, registre
pub mod round1;    // decrypt_round1                       (initiateur)
pub mod round2;    // h1_buckets, h1_labels, h2_buckets, decrypt_round2
pub mod export;    // write_intersection_csv               (initiateur)

use std::collections::HashMap;

// ── API par rôle ─────────────────────────────────────────────────────────────
pub use prologue::{prepare_csv, ColumnDictionary, PreparedDataset, PatientRecord};
pub use round1::decrypt_round1;
pub use round2::{h1_buckets, h1_labels, h2_buckets, decrypt_round2};
pub use export::write_intersection_csv;

// ── Étapes communes, ré-exportées depuis dpeg_shared ─────────────────────────
pub use dpeg_shared::exactmatch::{
    alg01_setup as keygen,            // (pk, sk) — APPELÉ PAR L'INITIATEUR
    build_edb as build_database,
    compute_n,
    derive_match_key,                 // clé d'un patient (utilisé par prologue)
    Edb, KeaCt, MapLocal, MatchKey,
};
pub use dpeg_shared::paillier::p_keygen::p_keygen::{PublicKey, SecretKey};
pub use dpeg_shared::crypto_error::crypto_error::CryptoError;

// ── KEA (Paillier P², intégrité CCA1) ────────────────────────────────────────
// L'initiateur génère la clé KEA après keygen :
//   let (pk, sk) = keygen(bits)?;
//   let kea = paillier_kea_keygen(&pk)?;   // kea.ct_delta (public), kea.psy (secret)
// ct_delta est distribué avec pk ; psy reste chez l'initiateur avec sk.
pub use dpeg_shared::paillier_kea::{
    KeyPairKEA, paillier_kea_keygen, paillier_kea_encrypt, paillier_kea_decrypt,
};

/// Nombre de candidats par position : le PARTICIPANT le calcule et le transmet
/// à l'INITIATEUR (via le backend, canal direct) pour `h1_labels`.
pub fn counts_of(b: &HashMap<usize, Vec<KeaCt>>) -> HashMap<usize, usize> {
    b.iter().map(|(&p, v)| (p, v.len())).collect()
}
