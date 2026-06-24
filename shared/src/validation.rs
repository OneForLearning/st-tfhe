// ─────────────────────────────────────────────────────────────
// validation.rs — Validateurs défensifs pour les données reçues
//
// Toutes les fonctions de ce module sont conçues pour être appelées
// EXACTEMENT après réception d'une donnée venant du réseau, AVANT
// que cette donnée soit utilisée dans une opération cryptographique.
//
// Objectif : empêcher tout crash du processus (panic, OOM, etc.)
// en transformant les données invalides en CryptoError typées.
// ─────────────────────────────────────────────────────────────

use num_traits::Zero;

use crate::crypto_error::crypto_error::CryptoError;
use crate::paillier::p_keygen::p_keygen::PublicKey;
use crate::exactmatch::types::Edb;

/// Taille maximale d'un payload réseau (protection DoS).
/// 64 Mo : assez large pour Paillier 4096 bits avec EDB de 1M cases,
/// mais empêche un attaquant de provoquer une OOM avec une longueur
/// arbitraire.
pub const MAX_NETWORK_PAYLOAD: usize = 64 * 1024 * 1024;

/// Nombre maximal de candidats acceptés dans une EDB
/// (protection DoS sur les buckets Round 2).
pub const MAX_EDB_ENTRIES: usize = 16_777_216;  // 2^24

// ─────────────────────────────────────────────────────────────
// Validateurs de payload réseau
// ─────────────────────────────────────────────────────────────

/// Vérifie qu'un payload reçu ne dépasse pas MAX_NETWORK_PAYLOAD.
/// À appeler AVANT toute allocation de buffer de cette taille.
pub fn validate_payload_size(actual: usize) -> Result<(), CryptoError> {
    if actual > MAX_NETWORK_PAYLOAD {
        return Err(CryptoError::NetworkPayloadTooLarge {
            actual,
            maximum: MAX_NETWORK_PAYLOAD,
        });
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────
// Validateurs de clé publique
// ─────────────────────────────────────────────────────────────

/// Vérifie qu'une PublicKey reçue est structurellement valide.
///
/// Vérifications effectuées :
///   1. n != 0 et n ≥ 2048 bits (sécurité Paillier minimale)
///   2. n_squared == n × n (cohérence)
///   3. g != 0 et g < n^2
///   4. gcd(g, n^2) = 1 (g doit être inversible — sinon le chiffrement ne fonctionne pas)
pub fn validate_public_key(pk: &PublicKey) -> Result<(), CryptoError> {
    // 1. n doit être non nul et de taille suffisante
    if pk.n.is_zero() {
        return Err(CryptoError::InvalidPublicKey {
            reason: "n = 0".to_string(),
        });
    }
    let n_bits = pk.n.bits();
    if n_bits < 2048 {
        return Err(CryptoError::InvalidPublicKey {
            reason: format!("n trop petit : {n_bits} bits (minimum 2048)"),
        });
    }

    // 2. Cohérence n_squared == n × n
    if pk.n_squared != &pk.n * &pk.n {
        return Err(CryptoError::InvalidPublicKey {
            reason: "n_squared != n × n (clé corrompue ou falsifiée)".to_string(),
        });
    }

    // 3. g doit être dans [1, n^2)
    if pk.g.is_zero() {
        return Err(CryptoError::InvalidPublicKey {
            reason: "g = 0".to_string(),
        });
    }
    if pk.g >= pk.n_squared {
        return Err(CryptoError::InvalidPublicKey {
            reason: "g >= n² (hors plage)".to_string(),
        });
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────
// Validateurs d'EDB (table chiffrée)
// ─────────────────────────────────────────────────────────────

/// Vérifie que la taille d'une EDB correspond au N attendu.
pub fn validate_edb_size(edb: &Edb, expected_n: usize) -> Result<(), CryptoError> {
    if edb.len() != expected_n {
        return Err(CryptoError::InvalidEdbSize {
            expected: expected_n,
            actual:   edb.len(),
        });
    }
    if edb.len() > MAX_EDB_ENTRIES {
        return Err(CryptoError::NetworkPayloadTooLarge {
            actual:  edb.len(),
            maximum: MAX_EDB_ENTRIES,
        });
    }
    Ok(())
}

/// Vérifie que chaque chiffré dans EDB est dans [1, n^2).
/// Un chiffré de 0 est invalide (c = 0 dans Paillier est impossible
/// pour un chiffrement légitime — c'est nécessairement une attaque
/// ou une corruption).
/// Vérifie que chaque chiffré KEA dans EDB est valide : ses DEUX composantes
/// (Enc(m), Enc(ψ·m)) doivent être dans [1, n²). Une composante nulle est
/// nécessairement une attaque ou une corruption.
pub fn validate_edb_ciphertexts(
    edb: &Edb,
    pk:  &PublicKey,
) -> Result<(), CryptoError> {
    for (i, c) in edb.iter().enumerate() {
        // c = (c0, c1) : paire KEA.
        if c.0.is_zero() || c.1.is_zero() {
            return Err(CryptoError::NetworkMalformedMessage {
                peer:   "EDB sender".to_string(),
                reason: format!("composante de chiffré nulle à la position {i}"),
            });
        }
        if c.0 >= pk.n_squared || c.1 >= pk.n_squared {
            return Err(CryptoError::CiphertextOutOfRange);
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────
// Validateurs de MatchedPos
// ─────────────────────────────────────────────────────────────

/// Vérifie que les positions reçues sont dans [0, N).
/// Empêche un H1 malveillant de demander à H2 de chiffrer des candidats
/// à des positions hors plage (ce qui crasherait l'accès à MapLocal).
pub fn validate_matched_positions(
    pos: &[usize],
    n:   usize,
) -> Result<(), CryptoError> {
    if pos.len() > MAX_EDB_ENTRIES {
        return Err(CryptoError::NetworkPayloadTooLarge {
            actual:  pos.len(),
            maximum: MAX_EDB_ENTRIES,
        });
    }
    for &p in pos {
        if p >= n {
            return Err(CryptoError::NetworkMalformedMessage {
                peer:   "MatchedPos sender".to_string(),
                reason: format!("position {p} ≥ N ({n})"),
            });
        }
    }
    Ok(())
}
