// ─────────────────────────────────────────────────────────────
// exactmatch/mod.rs — Module exactmatch côté dpeg_shared
//
// Contient les éléments du protocole utilisés par PLUSIEURS rôles :
//   types       → Edb, MapLocal, constantes, domaines
//   csv_reader  → chargement des fichiers CSV patients (H1, H2)
//   hash        → hash_pos, encode_id (H1, H2)
//   crypto_utils→ random_nonzero (H1, H2, Server), mod_inverse (Server)
//   setup       → alg01_setup (H1 only), compute_n (tous)
//   edb         → build_edb (H1, H2)
//
// Les fonctions spécifiques à un rôle sont dans les crates respectives :
//   h1/src/round1.rs  → decrypt_round1
//   h1/src/round2.rs  → h1_buckets, decrypt_round2
//   h1/src/export.rs  → write_intersection_csv
//   h2/src/round2.rs  → h2_buckets
//   server/src/exactmatch/hom_ops.rs → he_add, he_sub, he_smul
//   server/src/exactmatch/round1.rs  → eval_round1
//   server/src/exactmatch/round2.rs  → eval_round2
// ─────────────────────────────────────────────────────────────

pub mod types;
pub mod csv_reader;
pub mod canonical;
pub mod hash;
pub mod crypto_utils;
pub mod setup;
pub mod edb;
pub mod binned_psi;

// ── Re-exports publics ───────────────────────────────────────
pub use types::{DEFAULT_BETA, DEFAULT_KEY_BITS, Edb, KeaCt, MapLocal, MatchKey};
pub use csv_reader::{load_nss_from_csv, load_patient_map};
pub use canonical::{
    normalize_name, normalize_date, normalize_nss,
    canonical_composite, derive_match_key, key_hex,
};
pub use hash::{hash_pos, encode_id};
pub use crypto_utils::{random_nonzero, mod_inverse};
pub use setup::{alg01_setup, compute_n};
pub use edb::{build_edb, build_edb_seq};
pub use binned_psi::{hash_bin, partition_into_bins, compute_num_bins, BinStats};
