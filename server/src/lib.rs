// ─────────────────────────────────────────────────────────────
// lib.rs (Server) — Interface bibliothèque de la crate dpeg_server
//
// Le module FHEnymisation (HEpseudo) a été retiré.
// Le serveur n'exécute que des opérations homomorphes Depth-0.
// ─────────────────────────────────────────────────────────────

pub mod exactmatch;
pub mod fiore_catalano;

pub use exactmatch::round1::eval_round1;
pub use exactmatch::round2::eval_round2;
pub use exactmatch::hom_ops::{he_add, he_sub, he_smul};
