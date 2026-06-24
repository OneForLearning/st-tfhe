// ─────────────────────────────────────────────────────────────
// edb.rs — Construction de la table EDB chiffrée
//
// Alg.02/03 : H1 et H2 construisent chacun leur EDB + MapLocal
//
// SÉCURITÉ (CESTI) :
//   L'aléa `r` (masque de randomisation Paillier) est tiré EXCLUSIVEMENT
//   via OsRng (CSPRNG du système d'exploitation : getrandom/getentropy).
//   Aucun PRNG non-cryptographique n'intervient sur le chemin du chiffrement.
//   La sécurité IND-CPA de Paillier repose sur l'imprévisibilité de r.
//
// OPTIMISATIONS (v0.5) :
//   1. build_edb     : Phase 1 parallélisée (Rayon) — pour le mode classique
//   2. build_edb_seq : Phase 1 séquentielle      — pour le mode binné
//   3. EncCtx pré-converti : g, n, n² convertis en rug::Integer une seule fois
//   4. Enc(0) sans g^m     : encrypt_zero saute l'exponentiation g^0 = 1
// ─────────────────────────────────────────────────────────────

use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use rand_core::OsRng;
use rayon::prelude::*;
use rug::Integer;

use crate::paillier::p_keygen::p_keygen::PublicKey;
use crate::paillier::rug_bridge::{EncCtx, to_rug, from_rug};
use crate::crypto_error::crypto_error::CryptoError;

use super::types::{Edb, MapLocal, MatchKey};
use super::hash::hash_pos;

/// Alg.02/03 — VERSION PARALLÈLE (mode CLASSIQUE).
/// Phase 1 parallélisée sur les N cases via Rayon.
/// ⚠ Ne pas utiliser en mode binné (parallélisme imbriqué).
pub fn build_edb(
    data: &[MatchKey],
    pk:   &PublicKey,
    n:    usize,
    who:  &'static str,
) -> Result<(Edb, MapLocal), CryptoError> {
    if data.is_empty() {
        return Err(CryptoError::EmptyDatabase { which: who });
    }

    let ctx   = EncCtx::new(&pk.g, &pk.n, &pk.n_squared);
    let n_rug = to_rug(&pk.n);

    // ── Phase 1 : init PARALLÈLE. Chaque case = Enc(aléatoire). ──────────────
    // Une case de bruit doit être un chiffré valide indistinguable d'un Enc(0).
    // On utilise encrypt_zero (r^n mod n²) : 1 seul modpow, pas de g^m ni de
    // message aléatoire à tirer. r (CSPRNG) suffit à rendre la case opaque.
    let edb: Edb = (0..n)
        .into_par_iter()
        .map(|_idx| {
            // KEA-Enc(0) = (Enc(0), Enc(0)) : deux r^n indépendants.
            let r0 = random_r_osrng(&pk.n, &n_rug);
            let r1 = random_r_osrng(&pk.n, &n_rug);
            (from_rug(&ctx.encrypt_zero(&r0)), from_rug(&ctx.encrypt_zero(&r1)))
        })
        .collect();

    finalize_edb(edb, data, &ctx, &pk.n, &n_rug, n)
}

/// Alg.02/03 — VERSION SÉQUENTIELLE (mode BINNÉ).
/// Phase 1 en boucle simple : le parallélisme est au niveau des bins.
pub fn build_edb_seq(
    data: &[MatchKey],
    pk:   &PublicKey,
    n:    usize,
    who:  &'static str,
) -> Result<(Edb, MapLocal), CryptoError> {
    if data.is_empty() {
        return Err(CryptoError::EmptyDatabase { which: who });
    }

    let ctx   = EncCtx::new(&pk.g, &pk.n, &pk.n_squared);
    let n_rug = to_rug(&pk.n);

    // ── Phase 1 : init SÉQUENTIELLE (pas de Rayon imbriqué) ─────────────────
    let mut edb: Edb = Vec::with_capacity(n);
    for _ in 0..n {
        let r0 = random_r_osrng(&pk.n, &n_rug);
        let r1 = random_r_osrng(&pk.n, &n_rug);
        edb.push((from_rug(&ctx.encrypt_zero(&r0)), from_rug(&ctx.encrypt_zero(&r1))));
    }

    finalize_edb(edb, data, &ctx, &pk.n, &n_rug, n)
}

/// Phase 2 commune : écrasement des positions occupées par Enc(0).
/// Enc(0) = r^n mod n² (sans g^m). r tiré via OsRng.
fn finalize_edb(
    mut edb:   Edb,
    data:      &[MatchKey],
    ctx:       &EncCtx,
    n_big:     &BigUint,
    n_rug:     &Integer,
    n:         usize,
) -> Result<(Edb, MapLocal), CryptoError> {
    let mut map = MapLocal::new();
    for key in data {
        let p = hash_pos(key, n);
        // KEA-Enc(0) = (Enc(0), Enc(0)) ; ψ·0 = 0 → img_verif réussira.
        let r0 = random_r_osrng(n_big, n_rug);
        let r1 = random_r_osrng(n_big, n_rug);
        edb[p] = (from_rug(&ctx.encrypt_zero(&r0)), from_rug(&ctx.encrypt_zero(&r1)));
        map.entry(p).or_insert_with(Vec::new).push(*key); // MatchKey est Copy
    }
    Ok((edb, map))
}

/// Tire r aléatoire dans [1, n) via OsRng (CSPRNG OS), puis convertit en rug.
///
/// SÉCURITÉ : OsRng appelle getrandom(2)/getentropy(2), source d'entropie
/// du noyau, conforme aux exigences d'aléa cryptographique (CESTI/ANSSI).
/// La conversion BigUint→Integer est une simple copie d'octets (~256 ns).
#[inline]
fn random_r_osrng(n_big: &BigUint, _n_rug: &Integer) -> Integer {
    let mut rng = OsRng;
    // r ∈ [1, n) : garantit r ≠ 0 (nécessaire pour r ∈ Z*_n)
    let r_big = rng.gen_biguint_range(&BigUint::one(), n_big);
    to_rug(&r_big)
}
