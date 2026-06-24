// ─────────────────────────────────────────────────────────────
// types.rs — Types publics, constantes et domaines de hachage
// ─────────────────────────────────────────────────────────────

use num_bigint::BigUint;
use std::collections::HashMap;

// ── Constantes publiques ──────────────────────────────────────
pub const DEFAULT_BETA:     f64   = 1.0;
pub const DEFAULT_KEY_BITS: u64   = 2048;

// ── Domaines de séparation (internes au module) ───────────────
// Garantissent que hash_pos et encode_id ne partagent jamais
// le même espace de sortie, même pour un même identifiant.
pub(crate) const HASH_DOMAIN:   &[u8] = b"PSI-h-v1";
pub(crate) const ENCODE_DOMAIN: &[u8] = b"PSI-enc-v1";

// ── Types publics ─────────────────────────────────────────────

/// Clé de correspondance d'un patient = SHA-256 du composite canonique
/// (NSS, date de naissance, nom, prénom), de taille FIXE (32 octets).
///
/// Voir `canonical::derive_match_key`. Taille fixe → boucles à borne connue,
/// pas de fuite de longueur, zeroization triviale. Tous les hôpitaux doivent
/// produire cette clé via la MÊME fonction (canonical) pour que le PSI matche.
pub type MatchKey = [u8; 32];

/// Chiffré KEA (Paillier P², CCA1) : paire (Enc(m), Enc(ψ·m)).
/// La relation linéaire ψ·m est préservée par he_add/he_sub/he_smul,
/// ce qui permet la vérification d'intégrité au déchiffrement (img_verif).
pub type KeaCt = (BigUint, BigUint);

/// Table de chiffrés KEA de taille N.
/// EDB[i] = KEA-Enc(0) = (Enc(0), Enc(0)) pour toute case (occupée ou bruit).
pub type Edb = Vec<KeaCt>;

/// Table locale position -> liste de clés de correspondance.
/// Conservée chez l'hôpital, jamais transmise au Serveur.
pub type MapLocal = HashMap<usize, Vec<MatchKey>>;