// ─────────────────────────────────────────────────────────────
// binned_psi.rs — Utilitaires de partitionnement en bins
//
// Découpe H1 et H2 en B bins indépendants. Chaque bin est traité
// comme un PSI standard avec une table EDB N_b = next_pow2(β × max(|H1_b|,|H2_b|))
// bien plus petite que N global → tient en cache, parallélisable.
//
// hash_bin utilise le domaine BIN_DOMAIN, distinct de HASH_DOMAIN (hash.rs),
// pour garantir l'indépendance des deux fonctions de hachage.
// ─────────────────────────────────────────────────────────────

use sha2::{Sha256, Digest};
use num_bigint::BigUint;

const BIN_DOMAIN: &[u8] = b"PSI-bin-v1";

/// Assigne un identifiant à un bin : SHA-256(BIN_DOMAIN || id) mod num_bins.
/// Déterministe → un même id (même NSS) va dans le même bin chez H1 et H2.
pub fn hash_bin(id: &str, num_bins: usize) -> usize {
    let mut h = Sha256::new();
    h.update(BIN_DOMAIN);
    h.update(id.as_bytes());
    let digest = BigUint::from_bytes_be(&h.finalize());
    let rem = digest % BigUint::from(num_bins);
    rem.to_u64_digits().first().copied().unwrap_or(0) as usize
}

/// Partitionne une liste d'identifiants en `num_bins` bins.
pub fn partition_into_bins(data: &[String], num_bins: usize) -> Vec<Vec<String>> {
    let mut bins = vec![Vec::new(); num_bins];
    for id in data {
        bins[hash_bin(id, num_bins)].push(id.clone());
    }
    bins
}

/// Nombre de bins recommandé pour une taille cible de bin.
pub fn compute_num_bins(d1: usize, d2: usize, target_bin_size: usize) -> usize {
    let max = d1.max(d2);
    if max == 0 || target_bin_size == 0 { return 1; }
    ((max + target_bin_size - 1) / target_bin_size).max(1)
}

/// Statistiques de partitionnement pour les logs.
pub struct BinStats {
    pub num_bins:       usize,
    pub bins_non_vides: usize,
    pub bin_max:        usize,
    pub bin_min:        usize,
    pub bin_moyen:      f64,
}

impl BinStats {
    pub fn compute(bins_h1: &[Vec<String>], bins_h2: &[Vec<String>]) -> Self {
        let num_bins = bins_h1.len();
        let (mut non_vides, mut max_b, mut min_b, mut total) = (0usize, 0usize, usize::MAX, 0usize);
        for b in 0..num_bins {
            let sz = bins_h1[b].len().max(bins_h2[b].len());
            if sz > 0 {
                non_vides += 1;
                max_b = max_b.max(sz);
                min_b = min_b.min(sz);
                total += sz;
            }
        }
        let moyen = if non_vides > 0 { total as f64 / non_vides as f64 } else { 0.0 };
        BinStats {
            num_bins,
            bins_non_vides: non_vides,
            bin_max: max_b,
            bin_min: if non_vides == 0 { 0 } else { min_b },
            bin_moyen: moyen,
        }
    }
}
