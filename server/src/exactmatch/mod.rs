// ─────────────────────────────────────────────────────────────
// exactmatch/mod.rs (Serveur)
//
// Algorithmes homomorphes exécutés UNIQUEMENT par le Serveur.
// Le Serveur n'a accès qu'à pk et aux chiffrés ; jamais à sk
// ni aux NSS en clair ni à MatchedPos.
// ─────────────────────────────────────────────────────────────

pub mod hom_ops;
pub mod round1;
pub mod round2;

// Re-exports utiles
pub use round1::eval_round1;
pub use round2::eval_round2;
